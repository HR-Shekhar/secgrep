//! Multi-signal scoring. High entropy is a clue, not a proof.

use crate::finding::{Candidate, Finding, Signals, ValidityStatus};
use crate::redact::{fingerprint, redact};
use crate::remediate;

/// Shannon entropy in bits per byte. Random tokens often sit around 3.5–5.0.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in s.as_bytes() {
        freq[b as usize] += 1;
    }
    let len = s.len() as f64;
    let mut h = 0.0;
    for count in freq {
        if count == 0 {
            continue;
        }
        let p = count as f64 / len;
        h -= p * p.log2();
    }
    h
}

pub fn score(candidate: &Candidate) -> Finding {
    let mut notes = Vec::new();
    let mut why = Vec::new();

    let pattern = candidate.pattern_strength;
    notes.push(format!(
        "pattern signal {:.2} ({})",
        pattern, candidate.description
    ));
    why.push(format!("recognized pattern: {}", candidate.description));

    let (context, ctx_note) = context_signal(&candidate.line_text, &candidate.raw);
    notes.push(ctx_note.clone());
    if context.abs() > 0.01 {
        why.push(ctx_note);
    }

    let entropy_bits = shannon_entropy(&candidate.raw);
    let (entropy, ent_note) = entropy_signal(entropy_bits);
    notes.push(ent_note.clone());
    why.push(ent_note);

    let (file, file_note) = file_signal(&candidate.file);
    notes.push(file_note.clone());
    if file.abs() > 0.01 {
        why.push(file_note);
    }

    let mut confidence = pattern + context + entropy + file;
    if confidence < 0.0 {
        confidence = 0.0;
    }
    if confidence > 1.0 {
        confidence = 1.0;
    }

    Finding {
        rule_id: candidate.rule_id.clone(),
        file: candidate.file.clone(),
        line: candidate.line,
        column: candidate.column,
        category: candidate.category,
        redacted_preview: redact(&candidate.raw),
        confidence,
        severity: candidate.severity,
        detector: "pattern+heuristics".into(),
        status: ValidityStatus::Unknown,
        why,
        remediation: remediate::for_category(candidate.category),
        signals: Signals {
            pattern,
            context,
            entropy,
            entropy_bits,
            file,
            validity: 0.0,
            notes,
        },
        fingerprint: fingerprint(&candidate.raw),
    }
}

fn context_signal(line: &str, raw: &str) -> (f64, String) {
    let lower = line.to_ascii_lowercase();
    let raw_l = raw.to_ascii_lowercase();

    if is_env_reference(&lower) {
        return (
            -0.5,
            "context: looks like an environment-variable reference, not a literal secret".into(),
        );
    }
    if is_placeholder(&raw_l) || is_placeholder(&lower) {
        return (
            -0.45,
            "context: placeholder/example wording (YOUR_, EXAMPLE, changeme, ...)".into(),
        );
    }
    if is_uuid(&raw_l) {
        return (-0.3, "context: value looks like a UUID".into());
    }
    if is_hex_hash(&raw_l) {
        return (
            -0.25,
            "context: value looks like a hex hash, not a branded token".into(),
        );
    }

    let keywords = [
        "api_key",
        "apikey",
        "secret",
        "password",
        "token",
        "credential",
        "private_key",
        "access_key",
    ];
    if keywords.iter().any(|k| lower.contains(k)) {
        return (
            0.12,
            "context: surrounding assignment uses a secret-like name".into(),
        );
    }
    (0.0, "context: no extra variable-name signal".into())
}

fn entropy_signal(bits: f64) -> (f64, String) {
    let contrib = if bits >= 4.5 {
        0.12
    } else if bits >= 3.5 {
        0.08
    } else if bits >= 2.5 {
        0.02
    } else {
        -0.08
    };
    (
        contrib,
        format!("entropy: {bits:.2} bits/byte (contribution {contrib:+.2})"),
    )
}

fn file_signal(path: &str) -> (f64, String) {
    let p = path.replace('\\', "/").to_ascii_lowercase();
    if p.contains("/docs/") || p.ends_with(".md") || p.contains("readme") {
        return (
            -0.25,
            "file: documentation — examples are common false positives".into(),
        );
    }
    if p.contains("test") || p.contains("spec") || p.contains("fixture") {
        return (-0.15, "file: test/fixture path".into());
    }
    if p.contains(".min.js")
        || p.contains("/dist/")
        || p.contains("/vendor/")
        || p.contains("bundle")
    {
        return (-0.3, "file: generated/minified/vendor artifact".into());
    }
    if p.ends_with(".env")
        || p.contains("credential")
        || p.contains("secret")
        || p.contains("id_rsa")
    {
        return (0.12, "file: high-risk config/credential path".into());
    }
    if p.contains("config") {
        return (0.06, "file: config path".into());
    }
    (0.0, "file: ordinary source path".into())
}

fn is_env_reference(line: &str) -> bool {
    line.contains("os.getenv")
        || line.contains("os.environ")
        || line.contains("std::env::var")
        || line.contains("process.env")
        || line.contains("env[")
        || line.contains("getenv(")
}

fn is_placeholder(s: &str) -> bool {
    let needles = [
        "your_",
        "example",
        "changeme",
        "change_me",
        "placeholder",
        "dummy",
        "fake",
        "insert",
        "todo",
        "sample",
        "xxxx",
        "yyyy",
        "lorem",
        "test_token",
        "not-a-real",
        "notareal",
    ];
    needles.iter().any(|n| s.contains(n))
}

fn is_uuid(s: &str) -> bool {
    let re = regex::Regex::new(
        r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
    )
    .expect("uuid regex");
    re.is_match(s)
}

fn is_hex_hash(s: &str) -> bool {
    let n = s.len();
    if n != 32 && n != 40 && n != 64 {
        return false;
    }
    s.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn apply_validity(finding: &mut Finding, status: ValidityStatus) {
    finding.status = status;
    match status {
        ValidityStatus::FalsePositive => {
            finding.confidence *= 0.2;
            finding.signals.validity = -0.5;
            finding.why.push(
                "validator: classified as false positive (placeholder/synthetic, not a live check)"
                    .into(),
            );
        }
        ValidityStatus::Verified => {
            finding.confidence = (finding.confidence + 0.2).min(1.0);
            finding.signals.validity = 0.2;
            finding.why.push(
                "validator: verified (stronger than a regex match — still not a network check here)"
                    .into(),
            );
        }
        ValidityStatus::Likely => {
            finding.signals.validity = 0.08;
            finding.why.push("validator: likely".into());
        }
        ValidityStatus::Suspicious => {
            finding.signals.validity = 0.0;
            finding.why.push("validator: suspicious".into());
        }
        ValidityStatus::Unknown => {
            finding.signals.validity = 0.0;
            finding
                .why
                .push("validator: unknown (no live provider call was made)".into());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Category, Severity};

    fn cand(file: &str, line: &str, raw: &str, strength: f64) -> Candidate {
        Candidate {
            rule_id: "t".into(),
            file: file.into(),
            line: 1,
            column: 1,
            category: Category::ApiKey,
            severity: Severity::High,
            pattern_strength: strength,
            description: "test".into(),
            raw: raw.into(),
            line_text: line.into(),
        }
    }

    #[test]
    fn placeholder_in_docs_is_low() {
        let f = score(&cand(
            "README.md",
            r#"API_KEY = "YOUR_API_KEY_HERE_XXXX""#,
            "YOUR_API_KEY_HERE_XXXX",
            0.45,
        ));
        assert!(f.confidence < 0.5, "confidence was {}", f.confidence);
    }

    #[test]
    fn aws_like_key_in_source_is_high() {
        let key = format!("AKIA{}", "D7K3M2P9Q1W8X4YZ");
        let line = format!(r#"aws_access_key_id = "{key}""#);
        let f = score(&cand("config.py", &line, &key, 0.9));
        assert!(f.confidence >= 0.85, "confidence was {}", f.confidence);
    }

    #[test]
    fn entropy_of_repeated_chars_is_low() {
        let key = format!("AKIA{}", "D7K3M2P9Q1W8X4YZ");
        assert!(shannon_entropy("AAAAAAAAAAAAAAAA") < 1.0);
        assert!(shannon_entropy(&key) > 3.0);
    }
}
