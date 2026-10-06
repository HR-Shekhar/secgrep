use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::process::Command as StdCommand;
use tempfile::tempdir;

fn git(dir: &std::path::Path, args: &[&str]) {
    let status = StdCommand::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .status()
        .expect("git");
    assert!(status.success(), "git {:?} failed", args);
}

#[test]
fn history_shows_rotate_after_delete() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    git(root, &["init"]);
    git(root, &["config", "user.email", "test@example.com"]);
    git(root, &["config", "user.name", "Test"]);

    let key = format!("AKIA{}", "D7K3M2P9Q1W8X4YZ");

    // Commit A: introduce fake secret
    fs::write(
        root.join("config.py"),
        format!("aws_access_key_id = \"{key}\"\n"),
    )
    .unwrap();
    git(root, &["add", "config.py"]);
    git(root, &["commit", "-m", "A leak"]);

    // Commit B: delete secret
    fs::write(root.join("config.py"), "# cleaned\n").unwrap();
    git(root, &["add", "config.py"]);
    git(root, &["commit", "-m", "B delete"]);

    // Commit C: clean
    fs::write(root.join("README.md"), "ok\n").unwrap();
    git(root, &["add", "README.md"]);
    git(root, &["commit", "-m", "C clean"]);

    let mut cmd = Command::cargo_bin("secgrep").unwrap();
    cmd.current_dir(root).args(["history", "."]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Historical exposure"))
        .stdout(predicate::str::contains("YES"))
        .stdout(predicate::str::contains("not present"))
        .stdout(predicate::str::contains("ROTATE"))
        .stdout(predicate::str::contains(key).not());
}

#[test]
fn commit_wrapper_blocks_staged_secret() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    git(root, &["init"]);
    git(root, &["config", "user.email", "test@example.com"]);
    git(root, &["config", "user.name", "Test"]);

    // Empty initial commit so git commit works later
    fs::write(root.join("README.md"), "start\n").unwrap();
    git(root, &["add", "README.md"]);
    git(root, &["commit", "-m", "init"]);

    let key = format!("AKIA{}", "D7K3M2P9Q1W8X4YZ");
    fs::write(root.join("leak.py"), format!("aws_access_key_id = \"{key}\"\n")).unwrap();
    git(root, &["add", "leak.py"]);

    let mut cmd = Command::cargo_bin("secgrep").unwrap();
    cmd.current_dir(root)
        .args(["commit", "-m", "should fail"]);
    cmd.assert().failure().code(1);

    // Ensure commit was not created
    let log = StdCommand::new("git")
        .arg("-C")
        .arg(root)
        .args(["log", "--oneline"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&log.stdout);
    assert!(!text.contains("should fail"));
}
