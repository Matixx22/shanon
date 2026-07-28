//! Platform layer (§3.5): openat-anchored directory traversal and atomic
//! no-replace publication, using `rustix`'s safe API.
//!
//! Directory traversal uses `os.open(..., dir_fd=...)`-style anchoring via
//! `rustix::fs::{openat, renameat_with}`. Traversal is entirely safe (rustix's
//! checked wrappers); the sole `unsafe` is the macOS `renamex_np` FFI call, which
//! rustix does not wrap off Linux (plan §7 done-criteria).
//!
//! Linux/macOS only in v1 (D2). Windows is dropped and documented.

use std::fs::File;
use std::io::Read;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Component, Path};

use rustix::fs::{self, FileType, Mode, OFlags};

/// Maximum bytes read from a single JSON member (`_MAX_MEMBER_UNCOMPRESSED`).
pub const MAX_MEMBER_UNCOMPRESSED: u64 = 512 * 1024 * 1024;
const HASH_CHUNK_SIZE: usize = 1024 * 1024;

/// A directory-traversal / read failure, carrying the exact `ValueError`
/// message so the CLI's `ABORTED - no output written: {exc}` line stays
/// byte-identical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraversalError(pub String);

impl TraversalError {
    fn new(msg: &str) -> Self {
        TraversalError(msg.to_string())
    }
}

impl std::fmt::Display for TraversalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TraversalError {}

fn dir_open_flags() -> OFlags {
    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::DIRECTORY | OFlags::NOFOLLOW
}

fn file_open_flags() -> OFlags {
    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW
}

/// Pin a directory root where openat-style traversal is available
/// (`_open_directory_root`). The root itself is opened with `O_NOFOLLOW`.
pub fn open_directory_root(path: &Path) -> Result<OwnedFd, TraversalError> {
    fs::open(path, dir_open_flags(), Mode::empty())
        .map_err(|_| TraversalError::new("safe directory traversal is unavailable"))
}

/// Read `path` (a descendant of `input_root`) through anchored `openat` hops,
/// re-`fstat`ing to reject any change during the read
/// (`_read_directory_member_anchored`).
pub fn read_directory_member_anchored(
    input_root: &Path,
    path: &Path,
    root_fd: BorrowedFd<'_>,
) -> Result<Vec<u8>, TraversalError> {
    let relative = path
        .strip_prefix(input_root)
        .map_err(|_| TraversalError::new("unable to safely read directory member"))?;

    let mut parts: Vec<&std::ffi::OsStr> = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => parts.push(part),
            _ => return Err(TraversalError::new("unsafe directory member path")),
        }
    }
    if parts.is_empty() {
        return Err(TraversalError::new("unsafe directory member path"));
    }

    let io_err = || TraversalError::new("unable to safely read directory member");

    // Walk every intermediate directory with openat, never following symlinks.
    let mut current: Option<OwnedFd> = None;
    for part in &parts[..parts.len() - 1] {
        let dir = current.as_ref().map(|f| f.as_fd()).unwrap_or(root_fd);
        let next = fs::openat(dir, *part, dir_open_flags(), Mode::empty()).map_err(|_| io_err())?;
        current = Some(next);
    }
    let dir = current.as_ref().map(|f| f.as_fd()).unwrap_or(root_fd);
    let fd = fs::openat(
        dir,
        parts[parts.len() - 1],
        file_open_flags(),
        Mode::empty(),
    )
    .map_err(|_| io_err())?;

    let before = fs::fstat(&fd).map_err(|_| io_err())?;
    if FileType::from_raw_mode(before.st_mode as _) != FileType::RegularFile {
        return Err(TraversalError::new(
            "directory contains a non-regular JSON member",
        ));
    }
    if before.st_size as u64 > MAX_MEMBER_UNCOMPRESSED {
        return Err(TraversalError::new(
            "directory contains an oversized JSON member",
        ));
    }

    let mut file = File::from(fd);
    let raw = read_bounded(&mut file, MAX_MEMBER_UNCOMPRESSED)?;

    let after = fs::fstat(file.as_fd()).map_err(|_| io_err())?;
    let changed = before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || before.st_size != after.st_size
        || before.st_mtime != after.st_mtime
        || before.st_mtime_nsec != after.st_mtime_nsec
        || raw.len() as i64 != after.st_size as i64;
    if changed {
        return Err(TraversalError::new("input member changed during read"));
    }
    Ok(raw)
}

/// Read at most `maximum` bytes, erroring if the source exceeds it
/// (`_read_bounded`).
pub fn read_bounded(source: &mut impl Read, maximum: u64) -> Result<Vec<u8>, TraversalError> {
    let mut out: Vec<u8> = Vec::new();
    let mut buf = vec![0u8; HASH_CHUNK_SIZE];
    let mut total: u64 = 0;
    loop {
        // Read one byte past the ceiling so overflow is detectable.
        let want = std::cmp::min(HASH_CHUNK_SIZE as u64, maximum - total + 1) as usize;
        let n = source
            .read(&mut buf[..want])
            .map_err(|_| TraversalError::new("unable to safely read directory member"))?;
        if n == 0 {
            return Ok(out);
        }
        total += n as u64;
        if total > maximum {
            return Err(TraversalError::new("JSON member exceeds maximum size"));
        }
        out.extend_from_slice(&buf[..n]);
    }
}

/// The outcome of an atomic no-replace rename (`_rename_no_replace`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenameError {
    /// The destination already exists (`errno::EEXIST` -> `FileExistsError`).
    Exists,
    /// The platform/filesystem cannot do a no-replace rename (normalized
    /// `ENOSYS`/`EINVAL`/`EOPNOTSUPP` -> `ENOTSUP`).
    Unsupported,
    /// Any other errno.
    Other(i32),
}

impl std::fmt::Display for RenameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RenameError::Exists => write!(f, "destination already exists"),
            RenameError::Unsupported => write!(f, "atomic no-replace rename is unavailable"),
            RenameError::Other(n) => write!(f, "rename failed (errno {n})"),
        }
    }
}

impl std::error::Error for RenameError {}

/// Atomically rename `stage` -> `destination`, refusing to replace an existing
/// destination. Linux uses `renameat2(RENAME_NOREPLACE)` via rustix; macOS/BSD
/// use `renamex_np(RENAME_EXCL)` (rustix exposes `renameat_with` on Linux only).
#[cfg(target_os = "linux")]
pub fn rename_no_replace(stage: &Path, destination: &Path) -> Result<(), RenameError> {
    use rustix::fs::{renameat_with, RenameFlags, CWD};
    use rustix::io::Errno;
    match renameat_with(CWD, stage, CWD, destination, RenameFlags::NOREPLACE) {
        Ok(()) => Ok(()),
        Err(Errno::EXIST) => Err(RenameError::Exists),
        Err(Errno::NOSYS) | Err(Errno::INVAL) | Err(Errno::OPNOTSUPP) => {
            Err(RenameError::Unsupported)
        }
        Err(e) => Err(RenameError::Other(e.raw_os_error())),
    }
}

/// macOS/BSD variant: the one FFI call in this module. `renamex_np(RENAME_EXCL)`
/// is the atomic no-replace primitive rustix does not wrap off Linux.
#[cfg(not(target_os = "linux"))]
pub fn rename_no_replace(stage: &Path, destination: &Path) -> Result<(), RenameError> {
    use std::os::unix::ffi::OsStrExt;
    let stage_c = std::ffi::CString::new(stage.as_os_str().as_bytes())
        .map_err(|_| RenameError::Other(libc::EINVAL))?;
    let dest_c = std::ffi::CString::new(destination.as_os_str().as_bytes())
        .map_err(|_| RenameError::Other(libc::EINVAL))?;
    // SAFETY: both pointers are valid NUL-terminated C strings that outlive the
    // call; renamex_np reads them and returns 0 / -1 with errno set.
    let rc = unsafe { libc::renamex_np(stage_c.as_ptr(), dest_c.as_ptr(), libc::RENAME_EXCL) };
    if rc == 0 {
        return Ok(());
    }
    match std::io::Error::last_os_error().raw_os_error().unwrap_or(0) {
        libc::EEXIST => Err(RenameError::Exists),
        libc::ENOSYS | libc::EINVAL | libc::ENOTSUP => Err(RenameError::Unsupported),
        other => Err(RenameError::Other(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// A private directory for one test. The name is the discriminator: tests in
    /// this module run on parallel threads and share a pid, and macOS quantizes
    /// the realtime clock to a microsecond, so a timestamp here is not unique
    /// enough to keep two tests off the same path.
    fn tmp(name: &str) -> std::path::PathBuf {
        let base = std::env::temp_dir().join(format!("shanon-plat-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&base).ok();
        std::fs::create_dir_all(&base).unwrap();
        base
    }

    #[test]
    fn anchored_read_returns_member_bytes() {
        let root = tmp("member-bytes");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        let target = root.join("sub").join("a.json");
        std::fs::write(&target, b"{\"data\": []}").unwrap();

        let root_fd = open_directory_root(&root).unwrap();
        let raw = read_directory_member_anchored(&root, &target, root_fd.as_fd()).unwrap();
        assert_eq!(raw, b"{\"data\": []}");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn anchored_read_rejects_parent_escape() {
        let root = tmp("parent-escape");
        let root_fd = open_directory_root(&root).unwrap();
        // A path that does not live beneath the root -> strip_prefix fails.
        let outside = root.parent().unwrap().join("elsewhere.json");
        let err = read_directory_member_anchored(&root, &outside, root_fd.as_fd()).unwrap_err();
        assert_eq!(err.0, "unable to safely read directory member");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn read_bounded_rejects_overflow() {
        let data = vec![7u8; 64];
        let mut cursor = std::io::Cursor::new(data);
        let err = read_bounded(&mut cursor, 32).unwrap_err();
        assert_eq!(err.0, "JSON member exceeds maximum size");
    }

    #[test]
    fn rename_no_replace_refuses_existing_destination() {
        let root = tmp("rename-no-replace");
        let stage = root.join("stage");
        let dest = root.join("dest");
        {
            let mut f = std::fs::File::create(&stage).unwrap();
            f.write_all(b"x").unwrap();
        }
        std::fs::write(&dest, b"y").unwrap();
        assert_eq!(
            rename_no_replace(&stage, &dest),
            Err(RenameError::Exists),
            "no-replace must refuse an occupied destination"
        );
        // A free destination succeeds.
        let dest2 = root.join("dest2");
        assert_eq!(rename_no_replace(&stage, &dest2), Ok(()));
        std::fs::remove_dir_all(&root).ok();
    }
}
