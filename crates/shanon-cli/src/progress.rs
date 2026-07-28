//! Terminal progress rendering for `shanon anonymize`.
//!
//! A run over a real collection takes minutes, and every one of those minutes
//! used to be silent. This draws a single self-rewriting line on **stderr** so
//! stdout stays a clean data surface.
//!
//! Two rules keep the byte-parity contract (§3.4) intact:
//!
//! * Nothing is drawn unless stderr is a terminal, or `--progress` forces it.
//!   Piped and captured stderr is therefore byte-identical to before, which is
//!   what the parity fixtures and the CLI tests replay.
//! * [`Reporter::finish`] clears the active line before any other diagnostic is
//!   written, so a skipped-member warning or an aborted-leak block never lands
//!   on top of a half-drawn bar.
//!
//! No dependency is used for this: `indicatif` would pull a tree into the binary
//! that handles Active Directory collections, and a throttled `\r` redraw is
//! small enough to read in one sitting.

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use shanon_core::progress::{Phase, ProgressEvent, ProgressSink};

/// Minimum wall-clock gap between redraws. Fast enough to look continuous, slow
/// enough that drawing never competes with the work being measured.
const REDRAW_INTERVAL: Duration = Duration::from_millis(100);

/// Width of the drawn bar, in characters.
const BAR_WIDTH: usize = 24;

/// Spinner frames for phases whose size is not known up front.
const SPINNER: [char; 4] = ['|', '/', '-', '\\'];

/// Whether progress should be drawn for this run.
///
/// An explicit flag always wins; otherwise a terminal on stderr opts in and a
/// pipe opts out.
pub fn should_render(force_on: bool, force_off: bool) -> bool {
    if force_off {
        return false;
    }
    if force_on {
        return true;
    }
    std::io::stderr().is_terminal()
}

struct State {
    phase: Phase,
    /// `None` while the running phase does not know its own size.
    total: Option<u64>,
    done: u64,
    started: Instant,
    last_draw: Instant,
    spinner: usize,
    /// True while an undrawn-over line is sitting on the terminal.
    line_open: bool,
}

/// Draws phase progress to stderr, one rewriting line at a time.
pub struct Reporter {
    state: Mutex<Option<State>>,
    /// Set once any line has been drawn, so `finish` knows whether to clear.
    dirty: AtomicBool,
}

impl Reporter {
    /// Build a reporter and the sink that feeds it.
    pub fn new() -> (Arc<Reporter>, ProgressSink) {
        let reporter = Arc::new(Reporter {
            state: Mutex::new(None),
            dirty: AtomicBool::new(false),
        });
        let sink_target = Arc::clone(&reporter);
        let sink: ProgressSink = Arc::new(move |event| sink_target.handle(event));
        (reporter, sink)
    }

    fn handle(&self, event: ProgressEvent) {
        // A poisoned lock would mean a panic mid-draw. Progress is cosmetic, so
        // recover the guard rather than propagate a panic into the pipeline.
        let mut guard = match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        match event {
            ProgressEvent::PhaseStarted { phase, total } => {
                let now = Instant::now();
                *guard = Some(State {
                    phase,
                    total,
                    done: 0,
                    started: now,
                    // Backdate so the opening frame draws immediately.
                    last_draw: now - REDRAW_INTERVAL,
                    spinner: 0,
                    line_open: false,
                });
                self.draw(guard.as_mut().expect("just installed"), true);
            }
            ProgressEvent::Advanced(units) => {
                if let Some(state) = guard.as_mut() {
                    state.done += units;
                    self.draw(state, false);
                }
            }
            ProgressEvent::PhaseFinished => {
                if let Some(state) = guard.as_mut() {
                    // Land on the true final count, then release the line.
                    self.draw(state, true);
                    let _ = writeln!(std::io::stderr());
                    let _ = std::io::stderr().flush();
                }
                *guard = None;
                self.dirty.store(false, Ordering::Relaxed);
            }
        }
    }

    fn draw(&self, state: &mut State, force: bool) {
        let now = Instant::now();
        if !force && now.duration_since(state.last_draw) < REDRAW_INTERVAL {
            return;
        }
        state.last_draw = now;
        state.spinner = state.spinner.wrapping_add(1);
        let elapsed = now.duration_since(state.started);

        let mut line = format!("{:<16} ", state.phase.label());
        match state.total {
            Some(total) if total > 0 => {
                let done = state.done.min(total);
                let filled = (BAR_WIDTH as u64 * done / total) as usize;
                line.push('[');
                for i in 0..BAR_WIDTH {
                    line.push(if i < filled { '#' } else { '-' });
                }
                line.push(']');
                let percent = 100 * done / total;
                line.push_str(&format!(
                    " {percent:>3}%  {}/{}  {}",
                    thousands(done),
                    thousands(total),
                    clock(elapsed)
                ));
                if done > 0 && done < total {
                    let remaining = elapsed.mul_f64((total - done) as f64 / done as f64);
                    line.push_str(&format!("  eta {}", clock(remaining)));
                }
            }
            _ => {
                let frame = SPINNER[state.spinner % SPINNER.len()];
                line.push_str(&format!("{frame}  "));
                if state.done > 0 {
                    line.push_str(&format!("{} objects  ", thousands(state.done)));
                }
                line.push_str(&clock(elapsed));
            }
        }

        let mut err = std::io::stderr();
        // Pad to the previous width so a shrinking line leaves no residue.
        let _ = write!(err, "\r{line:<78}");
        let _ = err.flush();
        state.line_open = true;
        self.dirty.store(true, Ordering::Relaxed);
    }

    /// Clear any half-drawn line so the next stderr write starts clean.
    ///
    /// Safe to call more than once, and safe to call when nothing was drawn.
    /// The CLI calls it unconditionally once the pipeline returns, because an
    /// aborted run leaves a phase open with no `PhaseFinished`.
    pub fn finish(&self) {
        let mut guard = match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let had_line = guard.as_ref().map(|s| s.line_open).unwrap_or(false)
            || self.dirty.load(Ordering::Relaxed);
        if had_line {
            let mut err = std::io::stderr();
            let _ = write!(err, "\r{:<78}\r", "");
            let _ = err.flush();
        }
        *guard = None;
        self.dirty.store(false, Ordering::Relaxed);
    }
}

/// Render a duration as `m:ss`, or `h:mm:ss` once it passes an hour.
fn clock(d: Duration) -> String {
    let secs = d.as_secs();
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 {
        format!("{h}:{m:02}:{s:02}")
    } else {
        format!("{m}:{s:02}")
    }
}

/// Group digits with `,` so six-figure object counts stay readable.
fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thousands_groups_from_the_right() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(7), "7");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1_000), "1,000");
        assert_eq!(thousands(48_213), "48,213");
        assert_eq!(thousands(1_234_567), "1,234,567");
    }

    #[test]
    fn clock_promotes_to_hours() {
        assert_eq!(clock(Duration::from_secs(0)), "0:00");
        assert_eq!(clock(Duration::from_secs(9)), "0:09");
        assert_eq!(clock(Duration::from_secs(75)), "1:15");
        assert_eq!(clock(Duration::from_secs(3_600)), "1:00:00");
        assert_eq!(clock(Duration::from_secs(3_725)), "1:02:05");
    }

    #[test]
    fn explicit_flags_override_terminal_detection() {
        assert!(!should_render(true, true), "--no-progress must win");
        assert!(should_render(true, false));
        assert!(!should_render(false, true));
    }
}
