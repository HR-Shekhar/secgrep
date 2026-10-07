use assert_cmd::Command;
use predicates::prelude::*;
use secgrep::config::Config;
use secgrep::engine;

#[test]
fn corpus_blocks_branded_cloud_keys() {
    let cfg = Config::defaults();
    // Bypass project secgrep.toml ignore of testdata by scanning path directly —
    // walk still reads files under the given root.
    let mut cfg = cfg;
    cfg.ignore_paths.retain(|p| p != "testdata");
    let (findings, stats) = engine::scan_path(std::path::Path::new("testdata/corpus"), &cfg)
        .expect("scan corpus");
    assert!(stats.parallel);
    assert!(stats.files_scanned >= 5);

    let rules: Vec<_> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(rules.iter().any(|r| *r == "aws-access-key"));
    assert!(rules.iter().any(|r| *r == "stripe-secret"));
    assert!(rules.iter().any(|r| *r == "openai-api-key"));
    assert!(rules.iter().any(|r| *r == "google-api-key"));
    assert!(rules.iter().any(|r| *r == "github-pat") || rules.iter().any(|r| *r == "slack-token"));

    let blocked = findings
        .iter()
        .filter(|f| f.should_block(cfg.min_confidence))
        .count();
    assert!(blocked >= 3, "expected several blocked findings, got {blocked}");
}

#[test]
fn corpus_cli_readable_and_redacted() {
    let secret = format!("AKIA{}", "D7K3M2P9Q1W8X4YZ");
    let mut cmd = Command::cargo_bin("secgrep").unwrap();
    cmd.args(["scan", "testdata/corpus", "--format", "text"]);
    cmd.assert()
        .failure()
        .code(1)
        .stdout(predicate::str::contains("secgrep"))
        .stdout(predicate::str::contains("BLOCK"))
        .stdout(predicate::str::contains("parallel"))
        .stdout(predicate::str::contains("ROTATE"))
        .stdout(predicate::str::contains(secret).not());
}

#[test]
fn sarif_output_valid_shape() {
    let mut cmd = Command::cargo_bin("secgrep").unwrap();
    cmd.args(["scan", "testdata/corpus", "--format", "sarif"]);
    cmd.assert()
        .failure()
        .stdout(predicate::str::contains("\"version\": \"2.1.0\""))
        .stdout(predicate::str::contains("secgrep"))
        .stdout(predicate::str::contains("\"results\""));
}

#[test]
fn rules_command_lists_new_detectors() {
    let mut cmd = Command::cargo_bin("secgrep").unwrap();
    cmd.arg("rules");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("stripe-secret"))
        .stdout(predicate::str::contains("openai-api-key"))
        .stdout(predicate::str::contains("google-api-key"));
}
