//! Write-only progress reporting for long anonymization runs (module 13).
//!
//! A run over a real collection takes minutes, so the CLI needs to show that
//! work is advancing. The channel carrying that signal is deliberately as narrow
//! as it can be: a [`ProgressEvent`] carries a phase tag and unit *counts*, and
//! nothing else. No field value, no path, no member name, and no registry or
//! engine state can travel through it.
//!
//! The narrowness is the point, not an accident:
//!
//! * Nothing observable through this channel can leak a source secret or a
//!   source filename (invariant 7) — no string ever enters an event.
//! * Nothing a sink does can influence anonymization (invariants 1 and 3) — the
//!   library never reads a sink back, so the published bytes are identical
//!   whether or not a sink is installed.
//!
//! Rendering lives entirely in `shanon-cli`. The library never draws a bar and
//! never writes to stdout or stderr on account of progress.

use std::sync::Arc;

/// Which stage of the pipeline is running.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Parse every member and allocate typed mappings (`discover_document`).
    Discovery,
    /// Transform each member, then independently verify it.
    TransformVerify,
    /// Stage, then atomically publish the collection and mapping file.
    Publish,
}

impl Phase {
    /// Short stable label for rendering.
    pub fn label(self) -> &'static str {
        match self {
            Phase::Discovery => "discovery",
            Phase::TransformVerify => "transform+verify",
            Phase::Publish => "publish",
        }
    }
}

/// A progress notification: a phase tag and counts, never a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgressEvent {
    /// A phase began. `total` is the exact unit count when it is known up front,
    /// and `None` when the phase has to run in order to learn its own size.
    PhaseStarted {
        /// The phase now running.
        phase: Phase,
        /// Total work units, when known before the phase starts.
        total: Option<u64>,
    },
    /// `units` more work units completed inside the running phase.
    Advanced(u64),
    /// The running phase finished. Emitted before the library writes any other
    /// diagnostic, so a renderer can clear its line first.
    PhaseFinished,
}

/// Where progress events go.
///
/// Cloning is cheap: the pipeline hands clones to the engine and the verifier so
/// both tick the same renderer.
pub type ProgressSink = Arc<dyn Fn(ProgressEvent) + Send + Sync>;

/// Deliver `event` when a sink is installed, otherwise do nothing.
pub(crate) fn emit(sink: Option<&ProgressSink>, event: ProgressEvent) {
    if let Some(sink) = sink {
        sink(event);
    }
}

/// Deliver a single completed work unit.
pub(crate) fn tick(sink: Option<&ProgressSink>) {
    emit(sink, ProgressEvent::Advanced(1));
}
