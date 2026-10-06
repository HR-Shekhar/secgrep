use secgrep::config::Config;
use secgrep::engine;
use secgrep::finding::ValidityStatus;

fn blocks(file: &str, content: &str) -> bool {
    let cfg = Config::defaults();
    engine::analyze_text(file, content, &cfg)
        .into_iter()
        .any(|f| f.should_block(cfg.min_confidence))
}

fn fake_aws_key() -> String {
    format!("AKIA{}", "D7K3M2P9Q1W8X4YZ")
}

#[test]
fn real_looking_aws_key_blocks() {
    let key = fake_aws_key();
    let content = format!(r#"aws_access_key_id = "{key}""#);
    assert!(blocks("config.py", &content));
}

#[test]
fn placeholder_does_not_block() {
    assert!(!blocks(
        "app.py",
        r#"API_KEY = "YOUR_API_KEY_HERE_XXXX""#,
    ));
}

#[test]
fn docs_example_does_not_block() {
    let key = fake_aws_key();
    let content = format!(r#"aws_access_key_id = "{key}"  # example only"#);
    assert!(!blocks("README.md", &content));
}

#[test]
fn env_reference_does_not_block() {
    assert!(!blocks(
        "app.py",
        r#"API_KEY = os.getenv("ABCDEFGHIJKLMNOP")"#,
    ));
}

#[test]
fn uuid_assignment_does_not_block() {
    assert!(!blocks(
        "app.py",
        r#"API_KEY = "550e8400-e29b-41d4-a716-446655440000""#,
    ));
}

#[test]
fn hex_hash_assignment_does_not_block() {
    assert!(!blocks(
        "app.py",
        r#"password = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855""#,
    ));
}

#[test]
fn minified_path_downranks() {
    assert!(!blocks(
        "dist/bundle.min.js",
        r#"API_KEY = "abcdefghijklmnopqrstuvwxyz12""#,
    ));
}

#[test]
fn low_entropy_dummy_does_not_block() {
    assert!(!blocks(
        "app.py",
        r#"password = "AAAAAAAAAAAAAAAA""#,
    ));
}

#[test]
fn synthetic_marks_placeholder_false_positive() {
    let cfg = Config::defaults();
    let findings = engine::analyze_text(
        "a.py",
        r#"API_KEY = "YOUR_API_KEY_HERE_XXXX""#,
        &cfg,
    );
    assert!(findings
        .iter()
        .any(|f| f.status == ValidityStatus::FalsePositive));
}
