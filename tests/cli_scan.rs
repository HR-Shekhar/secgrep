use assert_cmd::Command;
use predicates::prelude::*;

fn fake_aws_key() -> String {
    format!("AKIA{}", "D7K3M2P9Q1W8X4YZ")
}

#[test]
fn scan_corpus_blocks_and_redacts() {
    let secret = fake_aws_key();
    let mut cmd = Command::cargo_bin("secgrep").unwrap();
    cmd.args(["scan", "testdata/corpus", "--format", "text"]);
    cmd.assert()
        .failure()
        .code(1)
        .stdout(predicate::str::contains("aws-access-key"))
        .stdout(predicate::str::contains("ROTATE"))
        .stdout(predicate::str::contains("preview:"))
        .stdout(predicate::str::contains(secret).not());
}

#[test]
fn scan_corpus_json_has_no_raw_secret() {
    let secret = fake_aws_key();
    let mut cmd = Command::cargo_bin("secgrep").unwrap();
    cmd.args(["scan", "testdata/corpus", "--format", "json"]);
    cmd.assert()
        .failure()
        .code(1)
        .stdout(predicate::str::contains("\"status\": \"failed\""))
        .stdout(predicate::str::contains("\"raw\"").not())
        .stdout(predicate::str::contains(secret).not());
}

#[test]
fn scan_clean_fixture_exits_zero() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("ok.py"), "print('hello')\n").unwrap();
    let mut cmd = Command::cargo_bin("secgrep").unwrap();
    cmd.args(["scan"]).arg(dir.path());
    cmd.assert().success().code(0);
}

#[test]
fn help_lists_commands() {
    let mut cmd = Command::cargo_bin("secgrep").unwrap();
    cmd.arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("scan"))
        .stdout(predicate::str::contains("history"))
        .stdout(predicate::str::contains("commit"))
        .stdout(predicate::str::contains("install-hook"));
}
