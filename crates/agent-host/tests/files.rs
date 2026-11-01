//! File wiring through the host: canonical paths, `..` and symlink escapes,
//! case variants, `/home/a` versus `/home/ab`, and the check on the opened
//! descriptor.

mod common;

use std::os::unix::fs::symlink;
use std::path::Path;

use agent_host::fs::{self, FileError};
use agent_host::grant::Mode;
use agent_host::{CallError, Output, ToolCall, Vocabulary};
use common::{files, host_with, modes, under, write, TempDir};

fn read(path: &Path) -> ToolCall {
    ToolCall::ReadFile {
        path: path.to_path_buf(),
    }
}

fn write_call(path: &Path, contents: &str) -> ToolCall {
    ToolCall::WriteFile {
        path: path.to_path_buf(),
        contents: contents.into(),
    }
}

fn assert_denied(result: Result<Output, CallError>) {
    match result {
        Err(CallError::Denied {
            vocabulary: Vocabulary::Files,
            ..
        }) => {}
        other => panic!("expected a files denial, got {other:?}"),
    }
}

fn read_ok(result: Result<Output, CallError>) -> String {
    match result {
        Ok(Output::File(data)) => String::from_utf8(data).unwrap(),
        other => panic!("expected file contents, got {other:?}"),
    }
}

#[test]
fn reads_and_writes_inside_the_grant() {
    let t = TempDir::new("inside");
    write(&t.path("work/a.txt"), "alpha");
    let (mut host, agent) = host_with(&files(vec![under(&t.path("work"))]));
    assert_eq!(
        read_ok(host.call(agent, &read(&t.path("work/a.txt")))),
        "alpha"
    );
    host.call(agent, &write_call(&t.path("work/b.txt"), "beta"))
        .unwrap();
    host.call(agent, &write_call(&t.path("work/a.txt"), "A"))
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(t.path("work/b.txt")).unwrap(),
        "beta"
    );
    assert_eq!(std::fs::read_to_string(t.path("work/a.txt")).unwrap(), "A");
}

#[test]
fn denies_outside_the_grant_and_by_mode() {
    let t = TempDir::new("outside");
    write(&t.path("work/a.txt"), "alpha");
    write(&t.path("secret.txt"), "s");
    let (mut host, agent) = host_with(&files(vec![under(&t.path("work")), modes(&[Mode::Read])]));
    assert_denied(host.call(agent, &read(&t.path("secret.txt"))));
    assert_denied(host.call(agent, &write_call(&t.path("work/a.txt"), "x")));
    assert_denied(host.call(agent, &write_call(&t.path("work/new.txt"), "x")));
    assert!(!t.path("work/new.txt").exists());
    assert_eq!(
        std::fs::read_to_string(t.path("work/a.txt")).unwrap(),
        "alpha"
    );
}

#[test]
fn a_missing_file_outside_the_grant_is_denied_not_reported_missing() {
    let t = TempDir::new("missing");
    std::fs::create_dir_all(t.path("work")).unwrap();
    let (mut host, agent) = host_with(&files(vec![under(&t.path("work"))]));
    assert_denied(host.call(agent, &read(&t.path("nope/x"))));
    match host.call(agent, &read(&t.path("work/nope"))) {
        Err(CallError::Failed(_)) => {}
        other => panic!("expected not-found inside the grant, got {other:?}"),
    }
}

#[test]
fn home_a_is_not_a_prefix_of_home_ab() {
    let t = TempDir::new("prefix");
    write(&t.path("home/a/x"), "a");
    write(&t.path("home/ab/x"), "ab");
    let (mut host, agent) = host_with(&files(vec![under(&t.path("home/a"))]));
    assert_eq!(read_ok(host.call(agent, &read(&t.path("home/a/x")))), "a");
    assert_denied(host.call(agent, &read(&t.path("home/ab/x"))));
    assert_denied(host.call(agent, &write_call(&t.path("home/ab/y"), "y")));
    assert!(!t.path("home/ab/y").exists());
}

#[test]
fn dot_dot_cannot_escape() {
    let t = TempDir::new("dotdot");
    write(&t.path("work/a.txt"), "alpha");
    write(&t.path("secret.txt"), "s");
    let (mut host, agent) = host_with(&files(vec![under(&t.path("work"))]));
    assert_denied(host.call(agent, &read(&t.path("work/../secret.txt"))));
    assert_denied(host.call(agent, &read(&t.path("work/./../../secret.txt"))));
    // `..` past a name that does not exist yet is still resolved.
    assert_denied(host.call(agent, &write_call(&t.path("work/new/../../x"), "x")));
    assert!(!t.path("x").exists());
    // `..` that stays inside is fine.
    assert_eq!(
        read_ok(host.call(agent, &read(&t.path("work/sub/../a.txt")))),
        "alpha"
    );
}

#[test]
fn symlinks_cannot_escape() {
    let t = TempDir::new("symlink");
    write(&t.path("work/a.txt"), "alpha");
    write(&t.path("outside/secret.txt"), "s");
    symlink(t.path("outside/secret.txt"), t.path("work/link.txt")).unwrap();
    symlink(t.path("outside"), t.path("work/dir")).unwrap();
    let (mut host, agent) = host_with(&files(vec![under(&t.path("work"))]));
    assert_denied(host.call(agent, &read(&t.path("work/link.txt"))));
    assert_denied(host.call(agent, &read(&t.path("work/dir/secret.txt"))));
    assert_denied(host.call(agent, &write_call(&t.path("work/link.txt"), "x")));
    assert_denied(host.call(agent, &write_call(&t.path("work/dir/new.txt"), "x")));
    assert_eq!(
        std::fs::read_to_string(t.path("outside/secret.txt")).unwrap(),
        "s"
    );
    assert!(!t.path("outside/new.txt").exists());
    // `..` after a symlink applies to where the symlink leads, as the kernel
    // does: `work/dir/..` is the parent of `outside`, not `work`, so this is
    // `top.txt` at the top, even though lexically it would be `work/top.txt`.
    write(&t.path("work/top.txt"), "inside");
    write(&t.path("top.txt"), "top");
    assert_denied(host.call(agent, &read(&t.path("work/dir/../top.txt"))));
}

#[test]
fn a_symlink_into_the_grant_is_allowed_as_its_target() {
    let t = TempDir::new("symlink-in");
    write(&t.path("work/a.txt"), "alpha");
    symlink(t.path("work"), t.path("alias")).unwrap();
    let (mut host, agent) = host_with(&files(vec![under(&t.path("work"))]));
    assert_eq!(
        read_ok(host.call(agent, &read(&t.path("alias/a.txt")))),
        "alpha"
    );
}

#[test]
fn a_grant_prefix_given_through_a_symlink_names_its_target() {
    let t = TempDir::new("grant-symlink");
    write(&t.path("work/a.txt"), "alpha");
    symlink(t.path("work"), t.path("alias")).unwrap();
    let (mut host, agent) = host_with(&files(vec![under(&t.path("alias"))]));
    assert_eq!(
        read_ok(host.call(agent, &read(&t.path("work/a.txt")))),
        "alpha"
    );
}

#[test]
fn a_dangling_symlink_is_not_followed_for_a_write() {
    let t = TempDir::new("dangling");
    std::fs::create_dir_all(t.path("work")).unwrap();
    std::fs::create_dir_all(t.path("outside")).unwrap();
    symlink(t.path("outside/created.txt"), t.path("work/link.txt")).unwrap();
    let (mut host, agent) = host_with(&files(vec![under(&t.path("work"))]));
    assert!(host
        .call(agent, &write_call(&t.path("work/link.txt"), "x"))
        .is_err());
    assert!(!t.path("outside/created.txt").exists());
}

/// On a case-insensitive file system (macOS APFS by default), a differently
/// cased path names the same file. The host checks the name stored on disk,
/// so a case variant is allowed exactly when the stored path is, and a case
/// variant of a denied path stays denied.
#[test]
fn case_variants_cannot_escape() {
    let t = TempDir::new("case");
    write(&t.path("Work/Notes.txt"), "notes");
    write(&t.path("Secret/key.txt"), "s");
    let (mut host, agent) = host_with(&files(vec![under(&t.path("Work"))]));
    assert_denied(host.call(agent, &read(&t.path("SECRET/key.txt"))));
    assert_denied(host.call(agent, &read(&t.path("secret/KEY.TXT"))));
    assert_denied(host.call(agent, &read(&t.path("WORK/../secret/key.txt"))));
    assert_denied(host.call(agent, &write_call(&t.path("sEcReT/key.txt"), "x")));
    assert_eq!(
        std::fs::read_to_string(t.path("Secret/key.txt")).unwrap(),
        "s"
    );
    if common::case_insensitive(&t.0) {
        // The variant resolves to `Work/Notes.txt`, which the grant allows.
        assert_eq!(
            read_ok(host.call(agent, &read(&t.path("WORK/notes.TXT")))),
            "notes"
        );
        host.call(agent, &write_call(&t.path("work/NOTES.txt"), "new"))
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(t.path("Work/Notes.txt")).unwrap(),
            "new"
        );
        // The stored spelling is what is checked: a grant on one file does
        // not reach another file through a variant, and a variant of the
        // granted file is that file.
        let (mut host, agent) = host_with(&files(vec![under(&t.path("Work/Notes.txt"))]));
        assert_eq!(
            read_ok(host.call(agent, &read(&t.path("work/notes.txt")))),
            "new"
        );
        assert_denied(host.call(agent, &read(&t.path("secret/key.txt"))));
    } else {
        // Case-sensitive: the variant is another name, outside the grant.
        assert_denied(host.call(agent, &read(&t.path("WORK/Notes.txt"))));
    }
}

/// A component swapped for a symlink between the check and the open: the
/// check on the opened descriptor sees where the open landed.
#[test]
fn a_swap_after_the_check_is_caught_on_the_opened_descriptor() {
    struct SwapOnFirstCheck<'a> {
        work: &'a Path,
        outside: &'a Path,
        granted: &'a Path,
        calls: usize,
    }
    impl fs::Check for SwapOnFirstCheck<'_> {
        fn allows(&mut self, path: &Path) -> std::io::Result<bool> {
            self.calls += 1;
            if self.calls == 1 {
                // The first check passes on the real directory; then it is
                // replaced by a symlink to a directory outside the grant.
                std::fs::rename(self.work, self.work.with_extension("old"))?;
                symlink(self.outside, self.work)?;
            }
            Ok(path.starts_with(self.granted))
        }
    }

    let t = TempDir::new("swap");
    write(&t.path("work/sub/a.txt"), "alpha");
    write(&t.path("outside/a.txt"), "secret");
    let (work, outside) = (t.path("work/sub"), t.path("outside"));
    let mut check = SwapOnFirstCheck {
        work: &work,
        outside: &outside,
        granted: &work,
        calls: 0,
    };
    match fs::read(&t.path("work/sub/a.txt"), 1024, &mut check) {
        Err(FileError::Denied { path, opened: true }) => {
            assert_eq!(path, outside.join("a.txt"));
        }
        other => panic!("expected a denial on the opened descriptor, got {other:?}"),
    }

    // A write: the swapped component is above the file's directory, so the
    // directory opens, and the check on its descriptor sees where it is.
    write(&t.path("work2/sub/keep.txt"), "");
    write(&t.path("outside2/sub/keep.txt"), "");
    let (work, outside, granted) = (t.path("work2"), t.path("outside2"), t.path("work2/sub"));
    let mut check = SwapOnFirstCheck {
        work: &work,
        outside: &outside,
        granted: &granted,
        calls: 0,
    };
    match fs::write(&t.path("work2/sub/new.txt"), b"x", &mut check) {
        Err(FileError::Denied { path, opened: true }) => {
            assert_eq!(path, t.path("outside2/sub/new.txt"));
        }
        other => panic!("expected a denial on the opened directory, got {other:?}"),
    }
    assert!(!t.path("outside2/sub/new.txt").exists());

    // The file's own directory swapped: `O_NOFOLLOW` refuses to open it.
    write(&t.path("work3/sub/keep.txt"), "");
    std::fs::create_dir_all(t.path("outside3")).unwrap();
    let (work, outside) = (t.path("work3/sub"), t.path("outside3"));
    let mut check = SwapOnFirstCheck {
        work: &work,
        outside: &outside,
        granted: &work,
        calls: 0,
    };
    assert!(matches!(
        fs::write(&t.path("work3/sub/new.txt"), b"x", &mut check),
        Err(FileError::Io(_))
    ));
    assert!(!t.path("outside3/new.txt").exists());
}

#[test]
fn only_regular_files() {
    let t = TempDir::new("regular");
    std::fs::create_dir_all(t.path("work/dir")).unwrap();
    let (mut host, agent) = host_with(&files(vec![under(&t.path("work"))]));
    assert!(matches!(
        host.call(agent, &read(&t.path("work/dir"))),
        Err(CallError::Failed(_))
    ));
}

#[test]
fn relative_paths_are_refused() {
    let (mut host, agent) = host_with(&files(vec![]));
    assert!(matches!(
        host.call(agent, &read(Path::new("etc/passwd"))),
        Err(CallError::Failed(_))
    ));
}
