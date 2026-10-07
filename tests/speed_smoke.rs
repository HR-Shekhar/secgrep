use secgrep::config::Config;
use secgrep::engine;
use std::fs;
use tempfile::tempdir;

#[test]
fn parallel_scan_handles_many_small_files() {
    let dir = tempdir().unwrap();
    for i in 0..80 {
        fs::write(
            dir.path().join(format!("f{i}.txt")),
            format!("line {i}\nok\n"),
        )
        .unwrap();
    }
    // One planted fake key
    let key = format!("AKIA{}", "D7K3M2P9Q1W8X4YZ");
    fs::write(
        dir.path().join("secret.py"),
        format!("aws_access_key_id = \"{key}\"\n"),
    )
    .unwrap();

    let cfg = Config::defaults();
    let (findings, stats) = engine::scan_path(dir.path(), &cfg).unwrap();
    assert!(stats.parallel);
    assert!(stats.files_scanned >= 80);
    assert!(findings.iter().any(|f| f.rule_id == "aws-access-key"));
    // Should be well under a few seconds even in debug
    assert!(
        stats.duration_ms < 15_000,
        "scan too slow: {} ms",
        stats.duration_ms
    );
}
