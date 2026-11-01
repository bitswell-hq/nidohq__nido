//! The conditions a timing run records: the scheduler request, the
//! machine's state as the operating system reports it, and the build.

use std::process::Command;

use serde_json::{json, Value};

/// Ask the scheduler to run this thread at the user-interactive quality of
/// service, which macOS places on its fastest cores when they are free. macOS
/// offers no way to pin a thread to a core. Returns what was requested and
/// whether the call succeeded.
#[cfg(target_os = "macos")]
#[must_use]
pub fn prefer_fast_cores() -> Value {
    // `QOS_CLASS_USER_INTERACTIVE` in <sys/qos.h>.
    const QOS_CLASS_USER_INTERACTIVE: u32 = 0x21;
    extern "C" {
        fn pthread_set_qos_class_self_np(qos_class: u32, relative_priority: i32) -> i32;
    }
    // SAFETY: a libSystem call on the current thread with a valid QoS class
    // and relative priority 0; it reads and writes no memory of ours.
    let status = unsafe { pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0) };
    json!({ "thread_qos": "QOS_CLASS_USER_INTERACTIVE", "set": status == 0, "pinned": false })
}

#[cfg(not(target_os = "macos"))]
#[must_use]
pub fn prefer_fast_cores() -> Value {
    json!({ "thread_qos": "default", "set": false, "pinned": false })
}

fn output(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default()
}

/// The machine's state, as the operating system reports it: model, cores
/// by performance level, OS, power source, power mode, thermal notes, load.
#[must_use]
pub fn machine() -> Value {
    if cfg!(target_os = "macos") {
        json!({
            "cpu": output("sysctl", &["-n", "machdep.cpu.brand_string"]),
            "cores": (0..3).filter_map(|l| {
                let name = output("sysctl", &["-n", &format!("hw.perflevel{l}.name")]);
                (!name.is_empty()).then(|| json!({
                    "level": name,
                    "physical": output("sysctl", &["-n", &format!("hw.perflevel{l}.physicalcpu")]),
                }))
            }).collect::<Vec<_>>(),
            "os": format!("macOS {} ({})", output("sw_vers", &["-productVersion"]), output("sw_vers", &["-buildVersion"])),
            "power_source": output("pmset", &["-g", "batt"]).lines().next().unwrap_or_default(),
            "power_mode": output("pmset", &["-g"]).lines().find(|l| l.contains("powermode") || l.contains("lowpowermode")).map(str::trim).unwrap_or_default(),
            "thermal": output("pmset", &["-g", "therm"]).lines().map(str::trim).collect::<Vec<_>>(),
            "load_average": output("sysctl", &["-n", "vm.loadavg"]),
        })
    } else {
        json!({
            "cpu": output("sh", &["-c", "grep -m1 'model name' /proc/cpuinfo | cut -d: -f2-"]),
            "os": output("uname", &["-sr"]),
            "load_average": output("cat", &["/proc/loadavg"]),
        })
    }
}

/// The build this binary is.
#[must_use]
pub fn build() -> Value {
    json!({
        "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        "overflow_checks": "on (evaluation/agent-host/Cargo.toml [profile.release])",
        "target": format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS),
    })
}
