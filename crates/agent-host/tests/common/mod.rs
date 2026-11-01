#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use agent_host::grant::{FileCaveat, Grants, Mode};
use agent_host::{AgentId, Host};
use nido_key_keeper::MemoryKeyKeeper;

/// A fresh directory under the system temp dir, removed on drop. Its path is
/// canonical, so tests can compare it with what the host resolves.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(name: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "agent-host-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(std::fs::canonicalize(dir).unwrap())
    }

    pub fn path(&self, rel: &str) -> PathBuf {
        self.0.join(rel)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn write(path: &Path, contents: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

/// Whether the file system holding `dir` folds case (macOS APFS by default).
pub fn case_insensitive(dir: &Path) -> bool {
    let probe = dir.join("case-probe");
    std::fs::write(&probe, "").unwrap();
    let folds = dir.join("CASE-PROBE").exists();
    std::fs::remove_file(probe).unwrap();
    folds
}

pub fn files(caveats: Vec<FileCaveat>) -> Grants {
    Grants {
        files: caveats,
        ..Grants::default()
    }
}

pub fn under(path: &Path) -> FileCaveat {
    FileCaveat::PathUnder(path.to_str().unwrap().to_owned())
}

pub fn modes(list: &[Mode]) -> FileCaveat {
    FileCaveat::ModeIn(list.to_vec())
}

pub fn host_with(grants: &Grants) -> (Host<MemoryKeyKeeper>, AgentId) {
    let mut host = Host::new(MemoryKeyKeeper::new()).unwrap();
    let agent = host.issue(grants).unwrap();
    (host, agent)
}
