//! File wiring: canonical paths in, and the checked file is the opened one.
//!
//! A requested path becomes an action in two steps.
//!
//! 1. [`resolve`] turns it into the canonical path the kernel would reach:
//!    each existing prefix is canonicalized (`realpath`), which follows
//!    symlinks, applies `..` to the directory a symlink led to (as the kernel
//!    does, not lexically), and returns the names stored on disk, so on a
//!    case-insensitive file system `/W/Notes.TXT` resolves to `/w/notes.txt`.
//!    Components past the last existing one are appended as given (`.`
//!    dropped, `..` removing the previous appended name); they name nothing
//!    yet, so they hold no symlinks and no other spelling.
//! 2. The host checks that path, then opens it with `O_NOFOLLOW` on the last
//!    component and checks again on the path of the open descriptor itself
//!    (`F_GETPATH` on macOS, `/proc/self/fd` on Linux), which is where the
//!    descriptor actually points. The data read or written goes through that
//!    descriptor, so if a component was swapped for a symlink between the two
//!    steps, the second check sees where the open landed.
//!
//! A write to a file that does not exist yet opens its directory, checks the
//! directory descriptor's path joined with the file name, and creates the
//! file under that descriptor with `O_CREAT | O_EXCL | O_NOFOLLOW`, so the file
//! appears in the directory that was checked and nowhere else.
//!
//! Not covered: a file or directory renamed by another process after it was
//! opened and checked (the descriptor follows the inode, not the path), and
//! hard links. A grant names paths, so a hard link inside the grant to a file
//! outside it is allowed; the agent's tools cannot create links. An error
//! while resolving (a directory the host cannot search, a dangling symlink)
//! is reported before the check and so can tell an agent that something
//! exists at a path its grant does not cover: grants control access, not
//! information flow.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{Mode, OFlags};

/// The canonical form of the absolute path `path` (see the module docs).
///
/// # Errors
///
/// If `path` is relative, or a component cannot be read (a dangling symlink,
/// a directory the host cannot search, a file used as a directory).
pub fn resolve(path: &Path) -> io::Result<PathBuf> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not an absolute path", path.display()),
        ));
    }
    let mut out = PathBuf::from("/");
    // How many trailing components of `out` do not exist yet.
    let mut missing = 0usize;
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Prefix(_) => unreachable!("no path prefixes on unix"),
            Component::ParentDir => {
                // `out` is canonical up to its missing tail, so its parent is
                // the directory `..` reaches.
                out.pop();
                missing = missing.saturating_sub(1);
            }
            Component::Normal(name) => {
                let next = out.join(name);
                if missing > 0 {
                    out = next;
                    missing += 1;
                    continue;
                }
                match std::fs::symlink_metadata(&next) {
                    Ok(_) => out = std::fs::canonicalize(&next)?,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        out = next;
                        missing = 1;
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }
    Ok(out)
}

/// The components of the absolute path `path`, as the files vocabulary
/// takes them: `/a/b` is `["a", "b"]` and `/` is `[]`.
#[must_use]
pub fn components(path: &Path) -> Vec<Vec<u8>> {
    path.components()
        .filter_map(|c| match c {
            Component::Normal(name) => Some(name.as_bytes().to_vec()),
            _ => None,
        })
        .collect()
}

/// The path the open descriptor `fd` refers to.
///
/// # Errors
///
/// If the platform cannot report it.
pub fn fd_path(fd: impl AsFd) -> io::Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let path = rustix::fs::getpath(fd)?;
        Ok(PathBuf::from(OsStr::from_bytes(path.as_bytes())))
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        std::fs::read_link(format!("/proc/self/fd/{}", fd.as_fd().as_raw_fd()))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = fd;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no way to read a descriptor's path on this platform",
        ))
    }
}

/// What a file operation needs from the grant check: one call per checked
/// path, answering whether the files grant allows it in this operation's mode.
pub trait Check {
    /// Whether the grant allows this canonical path.
    ///
    /// # Errors
    ///
    /// If the check itself could not run; the operation stops.
    fn allows(&mut self, path: &Path) -> io::Result<bool>;
}

/// Why a file operation did not happen.
#[derive(Debug)]
pub enum FileError {
    /// The grant denied this path. `opened` is true when the denial came from
    /// the check on the open descriptor, which means the path changed between
    /// resolving and opening.
    Denied {
        path: PathBuf,
        opened: bool,
    },
    Io(io::Error),
}

impl From<io::Error> for FileError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<rustix::io::Errno> for FileError {
    fn from(e: rustix::io::Errno) -> Self {
        Self::Io(e.into())
    }
}

fn require(check: &mut impl Check, path: &Path, opened: bool) -> Result<(), FileError> {
    if check.allows(path)? {
        Ok(())
    } else {
        Err(FileError::Denied {
            path: path.to_path_buf(),
            opened,
        })
    }
}

fn regular_file(fd: OwnedFd) -> io::Result<File> {
    let file = File::from(fd);
    if file.metadata()?.is_file() {
        Ok(file)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ))
    }
}

/// Read the file at `path`, at most `limit` bytes, if `check` allows it.
///
/// # Errors
///
/// [`FileError::Denied`] when a check fails, [`FileError::Io`] otherwise.
pub fn read(path: &Path, limit: u64, check: &mut impl Check) -> Result<Vec<u8>, FileError> {
    let canonical = resolve(path)?;
    require(check, &canonical, false)?;
    // `O_NONBLOCK` so a FIFO does not block the open; anything but a regular
    // file is refused below.
    let fd = rustix::fs::open(
        &canonical,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    require(check, &fd_path(&fd)?, true)?;
    let mut data = Vec::new();
    regular_file(fd)?.take(limit).read_to_end(&mut data)?;
    Ok(data)
}

/// Replace or create the file at `path` with `data`, if `check` allows it.
///
/// # Errors
///
/// [`FileError::Denied`] when a check fails, [`FileError::Io`] otherwise.
pub fn write(path: &Path, data: &[u8], check: &mut impl Check) -> Result<(), FileError> {
    let canonical = resolve(path)?;
    require(check, &canonical, false)?;
    let (Some(dir), Some(name)) = (canonical.parent(), canonical.file_name()) else {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a file path").into());
    };
    let dir_fd = rustix::fs::open(
        dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    require(check, &fd_path(&dir_fd)?.join(name), true)?;

    let flags = OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let mut file = match rustix::fs::openat(&dir_fd, name, flags, Mode::empty()) {
        Ok(fd) => {
            // An existing file: check where the descriptor points, which is
            // the name stored on disk, before truncating it.
            require(check, &fd_path(&fd)?, true)?;
            let file = regular_file(fd)?;
            file.set_len(0)?;
            file
        }
        Err(rustix::io::Errno::NOENT) => File::from(rustix::fs::openat(
            &dir_fd,
            name,
            flags | OFlags::CREATE | OFlags::EXCL,
            Mode::from_raw_mode(0o644),
        )?),
        Err(e) => return Err(e.into()),
    };
    file.write_all(data)?;
    Ok(())
}
