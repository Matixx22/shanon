//! Platform layer (§3.5): anchored directory traversal, private file creation,
//! and atomic no-replace publication.
//!
//! Three backends, selected by `cfg`:
//!
//! * **Linux** — traversal is `openat`-anchored through `rustix`'s checked
//!   wrappers, and publication is `renameat2(RENAME_NOREPLACE)`. Entirely safe
//!   code.
//! * **macOS/BSD** — the same anchored traversal, but publication needs
//!   `renamex_np(RENAME_EXCL)`, which `rustix` wraps on Linux only. That FFI call
//!   is one of the two `unsafe` blocks in the crate.
//! * **Windows** — no `openat` and no relative-handle traversal without the NT
//!   API, so traversal is *path-based with explicit reparse-point refusal at
//!   every component* rather than descriptor-anchored. Publication is
//!   `MoveFileExW` with no `MOVEFILE_REPLACE_EXISTING`, the second `unsafe`
//!   block. See SECURITY.md: the Windows traversal guarantee is strictly weaker
//!   than the other two, and directory input is the only path it applies to.
//!
//! Everything a caller touches is platform-neutral: [`DirRoot`] is opaque, so no
//! file descriptor or handle type escapes into `pipeline`.

use std::fs::File;
use std::io::Read;
use std::path::{Component, Path};

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

/// A pinned directory root for anchored traversal (`_open_directory_root`).
///
/// Opaque by design: on Unix this is the `openat` anchor, on Windows it is a
/// directory handle held for the life of the read, and callers must not be able
/// to tell which.
///
/// The Windows backend never dereferences the handle — there is no
/// relative-open to hand it to — but holding it keeps the root directory pinned
/// for the whole traversal, which the dead-code lint has no way to see.
pub struct DirRoot(#[cfg_attr(windows, allow(dead_code))] File);

/// Split `path` into the component names below `input_root`, refusing anything
/// that is not a plain name (`..`, a root, a Windows drive prefix) or that does
/// not live beneath the root at all.
fn relative_parts<'a>(
    input_root: &Path,
    path: &'a Path,
) -> Result<Vec<&'a std::ffi::OsStr>, TraversalError> {
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
    Ok(parts)
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

// ---------------------------------------------------------------------------
// Path identity.
//
// Every containment guard in `pipeline` (mapping-not-inside-input,
// mapping-not-inside-output, output-not-inside-input) compares resolved paths.
// What "the same path" means is a filesystem property, so it belongs here.
// ---------------------------------------------------------------------------

/// Whether two resolved paths name the same location.
#[cfg(not(windows))]
pub fn paths_equal(a: &Path, b: &Path) -> bool {
    a == b
}

/// Whether `child` is `ancestor` or lies beneath it.
#[cfg(not(windows))]
pub fn path_within(child: &Path, ancestor: &Path) -> bool {
    child.starts_with(ancestor)
}

/// Windows filenames are case-insensitive, so `OUT\c.map.json` and
/// `out\c.map.json` are one file. A byte-wise comparison would let a mapping
/// file (which holds every real identifier) be written inside the output
/// collection that is about to be handed to a model.
///
/// Comparison is component-wise so that `out-2` is not treated as living inside
/// `out`, and folding is [`crate::casefold`] rather than `to_lowercase`
/// (invariant 4).
#[cfg(windows)]
pub fn paths_equal(a: &Path, b: &Path) -> bool {
    let mut x = a.components();
    let mut y = b.components();
    loop {
        match (x.next(), y.next()) {
            (None, None) => return true,
            (Some(p), Some(q)) if component_eq(p, q) => continue,
            _ => return false,
        }
    }
}

/// See [`paths_equal`]: same folding, prefix form.
#[cfg(windows)]
pub fn path_within(child: &Path, ancestor: &Path) -> bool {
    let mut c = child.components();
    for want in ancestor.components() {
        match c.next() {
            Some(got) if component_eq(got, want) => continue,
            _ => return false,
        }
    }
    true
}

#[cfg(windows)]
fn component_eq(a: Component<'_>, b: Component<'_>) -> bool {
    use crate::casefold::casefold;
    casefold(&a.as_os_str().to_string_lossy()) == casefold(&b.as_os_str().to_string_lossy())
}

// ---------------------------------------------------------------------------
// Unix backend.
// ---------------------------------------------------------------------------

#[cfg(unix)]
mod imp {
    use super::{
        read_bounded, relative_parts, DirRoot, RenameError, TraversalError, MAX_MEMBER_UNCOMPRESSED,
    };
    use std::fs::File;
    use std::os::fd::{AsFd, OwnedFd};
    use std::path::Path;

    use rustix::fs::{self, FileType, Mode, OFlags};

    fn dir_open_flags() -> OFlags {
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::DIRECTORY | OFlags::NOFOLLOW
    }

    fn file_open_flags() -> OFlags {
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW
    }

    pub fn open_directory_root(path: &Path) -> Result<DirRoot, TraversalError> {
        let fd = fs::open(path, dir_open_flags(), Mode::empty())
            .map_err(|_| TraversalError::new("safe directory traversal is unavailable"))?;
        Ok(DirRoot(File::from(fd)))
    }

    /// Walk to `path` through anchored `openat` hops, never following a symlink,
    /// and re-`fstat` to reject any change during the read.
    pub fn read_directory_member_anchored(
        input_root: &Path,
        path: &Path,
        root: &DirRoot,
    ) -> Result<Vec<u8>, TraversalError> {
        let parts = relative_parts(input_root, path)?;
        let io_err = || TraversalError::new("unable to safely read directory member");
        let root_fd = root.0.as_fd();

        // Walk every intermediate directory with openat, never following symlinks.
        let mut current: Option<OwnedFd> = None;
        for part in &parts[..parts.len() - 1] {
            let dir = current.as_ref().map(|f| f.as_fd()).unwrap_or(root_fd);
            let next =
                fs::openat(dir, *part, dir_open_flags(), Mode::empty()).map_err(|_| io_err())?;
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

    /// Owner-only (`0o600`) and refusing to clobber, so a mapping file is never
    /// world-readable for even an instant.
    pub fn create_private_file(path: &Path) -> std::io::Result<File> {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    }

    /// Owner-only (`0o700`) staging directory.
    pub fn create_private_dir(path: &Path) -> std::io::Result<()> {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(path)
    }

    /// Linux: `renameat2(RENAME_NOREPLACE)` via rustix, entirely safe.
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

    /// macOS/BSD: `renamex_np(RENAME_EXCL)` is the atomic no-replace primitive
    /// rustix does not wrap off Linux.
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
}

// ---------------------------------------------------------------------------
// Windows backend.
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod imp {
    use super::{
        read_bounded, relative_parts, DirRoot, RenameError, TraversalError, MAX_MEMBER_UNCOMPRESSED,
    };
    use std::fs::File;
    use std::path::Path;

    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

    /// `FILE_FLAG_BACKUP_SEMANTICS` — required to open a directory at all.
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    /// `FILE_FLAG_OPEN_REPARSE_POINT` — the closest Windows has to `O_NOFOLLOW`.
    /// Opening a symlink or junction with it and without backup semantics fails
    /// outright rather than silently following the link.
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    pub fn open_directory_root(path: &Path) -> Result<DirRoot, TraversalError> {
        let unavailable = || TraversalError::new("safe directory traversal is unavailable");
        let meta = std::fs::symlink_metadata(path).map_err(|_| unavailable())?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err(unavailable());
        }
        let handle = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|_| unavailable())?;
        Ok(DirRoot(handle))
    }

    /// Read `path` (a descendant of `input_root`) and reject any change during
    /// the read.
    ///
    /// Windows has no `openat`, and reaching relative-handle opens means dropping
    /// to `NtCreateFile`. Instead every component from the root down is stat'd
    /// and refused if it is a reparse point, and the leaf is opened with
    /// `FILE_FLAG_OPEN_REPARSE_POINT` so a symlinked member fails to open rather
    /// than resolving elsewhere. That closes the symlink-escape hole but not the
    /// race: a component swapped between its check and the open is not caught
    /// here the way an anchored `openat` hop catches it. SECURITY.md states this
    /// plainly; ZIP input is unaffected.
    pub fn read_directory_member_anchored(
        input_root: &Path,
        path: &Path,
        _root: &DirRoot,
    ) -> Result<Vec<u8>, TraversalError> {
        let parts = relative_parts(input_root, path)?;
        let io_err = || TraversalError::new("unable to safely read directory member");

        let mut walked = input_root.to_path_buf();
        for part in &parts[..parts.len() - 1] {
            walked.push(part);
            let meta = std::fs::symlink_metadata(&walked).map_err(|_| io_err())?;
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(io_err());
            }
        }
        walked.push(parts[parts.len() - 1]);

        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&walked)
            .map_err(|_| io_err())?;

        let before = file.metadata().map_err(|_| io_err())?;
        if !before.is_file() {
            return Err(TraversalError::new(
                "directory contains a non-regular JSON member",
            ));
        }
        if before.file_size() > MAX_MEMBER_UNCOMPRESSED {
            return Err(TraversalError::new(
                "directory contains an oversized JSON member",
            ));
        }

        let raw = read_bounded(&mut file, MAX_MEMBER_UNCOMPRESSED)?;

        // The `(st_dev, st_ino)` half of the Unix check has no stable equivalent
        // here (`MetadataExt::file_index` is still unstable), but it is defensive
        // there too: both stats go through one open handle, which pins the file
        // object for the whole read. Size and timestamps are what can actually
        // move underneath it.
        let after = file.metadata().map_err(|_| io_err())?;
        let changed = before.file_size() != after.file_size()
            || before.last_write_time() != after.last_write_time()
            || before.creation_time() != after.creation_time()
            || raw.len() as u64 != after.file_size();
        if changed {
            return Err(TraversalError::new("input member changed during read"));
        }
        Ok(raw)
    }

    /// Windows has no `umask` and no cheap owner-only creation mode: a new file
    /// inherits its parent directory's ACL. `create_new` still guarantees the
    /// no-clobber half of the contract. SECURITY.md tells Windows users to keep
    /// the mapping file under their user profile, whose default ACL is already
    /// owner + SYSTEM + Administrators.
    pub fn create_private_file(path: &Path) -> std::io::Result<File> {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
    }

    /// See [`create_private_file`]: inherits the parent ACL, fails if it exists.
    pub fn create_private_dir(path: &Path) -> std::io::Result<()> {
        std::fs::create_dir(path)
    }

    // Win32 status codes used below. Named rather than inlined so the match arms
    // read as the documented `MoveFileExW` failure modes.
    const ERROR_INVALID_FUNCTION: i32 = 1;
    const ERROR_FILE_EXISTS: i32 = 80;
    const ERROR_INVALID_PARAMETER: i32 = 87;
    const ERROR_ALREADY_EXISTS: i32 = 183;
    const ERROR_NOT_SUPPORTED: i32 = 50;

    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileExW(existing_name: *const u16, new_name: *const u16, flags: u32) -> i32;
    }

    /// UTF-16, NUL-terminated, and rejecting an interior NUL that would truncate
    /// the path Win32 actually sees.
    fn wide(path: &Path) -> Option<Vec<u16>> {
        use std::os::windows::ffi::OsStrExt;
        let mut buf: Vec<u16> = path.as_os_str().encode_wide().collect();
        if buf.contains(&0) {
            return None;
        }
        buf.push(0);
        Some(buf)
    }

    /// `MoveFileExW` with `dwFlags = 0`: no `MOVEFILE_REPLACE_EXISTING`, so an
    /// occupied destination fails instead of being overwritten, and no
    /// `MOVEFILE_COPY_ALLOWED`, so a cross-volume move fails rather than
    /// degrading into a non-atomic copy. This is the second `unsafe` block in the
    /// crate.
    pub fn rename_no_replace(stage: &Path, destination: &Path) -> Result<(), RenameError> {
        let stage_w = wide(stage).ok_or(RenameError::Other(ERROR_INVALID_PARAMETER))?;
        let dest_w = wide(destination).ok_or(RenameError::Other(ERROR_INVALID_PARAMETER))?;
        // SAFETY: both pointers are valid NUL-terminated UTF-16 strings that
        // outlive the call; MoveFileExW reads them and returns nonzero on success
        // or zero with the thread's last-error set.
        let rc = unsafe { MoveFileExW(stage_w.as_ptr(), dest_w.as_ptr(), 0) };
        if rc != 0 {
            return Ok(());
        }
        match std::io::Error::last_os_error().raw_os_error().unwrap_or(0) {
            ERROR_FILE_EXISTS | ERROR_ALREADY_EXISTS => Err(RenameError::Exists),
            ERROR_NOT_SUPPORTED | ERROR_INVALID_FUNCTION => Err(RenameError::Unsupported),
            other => Err(RenameError::Other(other)),
        }
    }
}

pub use imp::{
    create_private_dir, create_private_file, open_directory_root, read_directory_member_anchored,
    rename_no_replace,
};

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

        let root_dir = open_directory_root(&root).unwrap();
        let raw = read_directory_member_anchored(&root, &target, &root_dir).unwrap();
        assert_eq!(raw, b"{\"data\": []}");
        drop(root_dir);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn anchored_read_rejects_parent_escape() {
        let root = tmp("parent-escape");
        let root_dir = open_directory_root(&root).unwrap();
        // A path that does not live beneath the root -> strip_prefix fails.
        let outside = root.parent().unwrap().join("elsewhere.json");
        let err = read_directory_member_anchored(&root, &outside, &root_dir).unwrap_err();
        assert_eq!(err.0, "unable to safely read directory member");
        drop(root_dir);
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

    #[test]
    fn create_private_file_refuses_to_clobber() {
        let root = tmp("private-file");
        let path = root.join("map.json");
        create_private_file(&path)
            .unwrap()
            .write_all(b"{}")
            .unwrap();
        assert!(
            create_private_file(&path).is_err(),
            "an existing file must never be reopened for truncation"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// Owner-only creation is a Unix-only guarantee; SECURITY.md documents the
    /// Windows gap rather than this test asserting a mode that does not exist.
    #[cfg(unix)]
    #[test]
    fn private_file_and_dir_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let root = tmp("private-mode");
        let dir = root.join("stage");
        create_private_dir(&dir).unwrap();
        let file = dir.join("member.json");
        create_private_file(&file).unwrap();
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn containment_guards_do_not_match_a_partial_component() {
        assert!(!path_within(Path::new("/a/outer"), Path::new("/a/out")));
        assert!(path_within(Path::new("/a/out/x"), Path::new("/a/out")));
        assert!(paths_equal(Path::new("/a/out"), Path::new("/a/out")));
    }

    /// The guard that a byte-wise comparison would miss on a case-insensitive
    /// filesystem: a mapping file written into the output collection under a
    /// different spelling of the same directory.
    #[cfg(windows)]
    #[test]
    fn containment_guards_fold_case_on_windows() {
        assert!(paths_equal(
            Path::new(r"C:\Out\c.map.json"),
            Path::new(r"c:\out\C.MAP.JSON")
        ));
        assert!(path_within(
            Path::new(r"C:\OUT\collection_anon\x.json"),
            Path::new(r"C:\out\collection_anon")
        ));
    }
}
