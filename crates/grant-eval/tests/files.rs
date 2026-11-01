mod common;

use grant_eval::files::{allows, allows_all, holds, is_prefix, Action, Caveat, Mode};

fn path(components: &[&str]) -> Vec<Vec<u8>> {
    components.iter().map(|c| c.as_bytes().to_vec()).collect()
}

fn access(components: &[&str], mode: Mode) -> Action {
    Action {
        path: path(components),
        mode,
    }
}

#[test]
fn path_under() {
    let c = Caveat::PathUnder(path(&["home", "a"]));
    assert!(holds(&c, &access(&["home", "a"], Mode::Read)));
    assert!(holds(&c, &access(&["home", "a", "notes.txt"], Mode::Write)));
    assert!(holds(&c, &access(&["home", "a", "x", "y"], Mode::Execute)));
    assert!(!holds(&c, &access(&["home"], Mode::Read)));
    assert!(!holds(&c, &access(&[], Mode::Read)));
    assert!(!holds(&c, &access(&["home", "b"], Mode::Read)));
    assert!(!holds(&c, &access(&["etc", "a"], Mode::Read)));
}

#[test]
fn path_under_is_component_wise() {
    let c = Caveat::PathUnder(path(&["home", "a"]));
    assert!(!holds(&c, &access(&["home", "ab"], Mode::Read)));
    assert!(!holds(&c, &access(&["home", "ab", "x"], Mode::Read)));
    assert!(!is_prefix(&path(&["home", "a"]), &path(&["home", "ab"])));
    assert!(is_prefix(&path(&["home", "a"]), &path(&["home", "a", "b"])));
    // Joining components does not make a prefix either.
    assert!(!holds(&c, &access(&["homea"], Mode::Read)));
    assert!(!holds(
        &Caveat::PathUnder(path(&["home/a"])),
        &access(&["home", "a"], Mode::Read)
    ));
}

#[test]
fn empty_prefix_is_under_every_path() {
    let c = Caveat::PathUnder(vec![]);
    assert!(holds(&c, &access(&[], Mode::Read)));
    assert!(holds(&c, &access(&["etc", "passwd"], Mode::Write)));
}

#[test]
fn mode_in() {
    let read_only = Caveat::ModeIn(vec![Mode::Read]);
    assert!(holds(&read_only, &access(&["f"], Mode::Read)));
    assert!(!holds(&read_only, &access(&["f"], Mode::Write)));
    assert!(!holds(&read_only, &access(&["f"], Mode::Execute)));
    let read_write = Caveat::ModeIn(vec![Mode::Read, Mode::Write]);
    assert!(holds(&read_write, &access(&["f"], Mode::Write)));
    assert!(!holds(&read_write, &access(&["f"], Mode::Execute)));
    assert!(holds(
        &Caveat::ModeIn(vec![Mode::Execute]),
        &access(&["f"], Mode::Execute)
    ));
    assert!(!holds(&Caveat::ModeIn(vec![]), &access(&["f"], Mode::Read)));
}

#[test]
fn empty_grant_allows_everything() {
    assert!(allows(&[], &access(&["etc", "shadow"], Mode::Write)));
    assert!(allows_all(
        &[],
        &[access(&[], Mode::Execute), access(&["x"], Mode::Read)]
    ));
}

#[test]
fn read_only_under_a_directory() {
    let grant = [
        Caveat::PathUnder(path(&["home", "a"])),
        Caveat::ModeIn(vec![Mode::Read]),
    ];
    assert!(allows(&grant, &access(&["home", "a", "f"], Mode::Read)));
    assert!(!allows(&grant, &access(&["home", "a", "f"], Mode::Write)));
    assert!(!allows(&grant, &access(&["home", "ab", "f"], Mode::Read)));
    assert!(!allows_all(
        &grant,
        &[
            access(&["home", "a", "f"], Mode::Read),
            access(&["home", "a", "g"], Mode::Write),
        ]
    ));
}

const N_CAVEATS: usize = 8;

fn caveat(i: usize) -> Caveat {
    match i {
        0 => Caveat::PathUnder(path(&["home", "a"])),
        1 => Caveat::PathUnder(path(&["home"])),
        2 => Caveat::PathUnder(vec![]),
        3 => Caveat::PathUnder(path(&["home", "ab"])),
        4 => Caveat::ModeIn(vec![Mode::Read]),
        5 => Caveat::ModeIn(vec![Mode::Read, Mode::Write]),
        6 => Caveat::ModeIn(vec![Mode::Execute]),
        7 => Caveat::ModeIn(vec![]),
        _ => unreachable!(),
    }
}

const N_ACTIONS: usize = 9;

fn action(i: usize) -> Action {
    match i {
        0 => access(&["home", "a"], Mode::Read),
        1 => access(&["home", "a", "f"], Mode::Write),
        2 => access(&["home", "ab"], Mode::Read),
        3 => access(&["home", "ab", "f"], Mode::Execute),
        4 => access(&["home"], Mode::Read),
        5 => access(&[], Mode::Write),
        6 => access(&["etc", "passwd"], Mode::Read),
        7 => access(&["home", "a", "x", "y"], Mode::Execute),
        8 => access(&["homea"], Mode::Read),
        _ => unreachable!(),
    }
}

fn mode_index(m: &Mode) -> u8 {
    match m {
        Mode::Read => 0,
        Mode::Write => 1,
        Mode::Execute => 2,
    }
}

/// The files semantics in plain Rust.
fn reference(c: &Caveat, a: &Action) -> bool {
    match c {
        Caveat::PathUnder(prefix) => a.path.starts_with(prefix),
        Caveat::ModeIn(list) => list.iter().any(|m| mode_index(m) == mode_index(&a.mode)),
    }
}

#[test]
fn exhaustive_attenuation_and_reference_agreement() {
    let seen = common::check_exhaustive(caveat, N_CAVEATS, action, N_ACTIONS, reference);
    assert!(seen.checks > 100_000, "{seen:?}");
}
