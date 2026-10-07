//! Validity is stronger than a regex match.
//! Live network checks run only when the user explicitly enables `--verify`.

use crate::finding::{Candidate, ValidityStatus};

pub trait Validator {
    fn name(&self) -> &'static str;
    fn validate(&self, candidate: &Candidate) -> ValidityStatus;
}

/// Default validator. Looks at the string itself. Never opens a socket.
pub struct SyntheticValidator;

impl Validator for SyntheticValidator {
    fn name(&self) -> &'static str {
        "synthetic"
    }

    fn validate(&self, candidate: &Candidate) -> ValidityStatus {
        let blob = format!("{} {}", candidate.raw, candidate.line_text).to_ascii_lowercase();
        const MARKERS: &[&str] = &[
            "example",
            "placeholder",
            "changeme",
            "your_api",
            "your_secret",
            "dummy",
            "fake",
            "xxxx",
            "not-a-real",
            "notareal",
            "insert_key",
            "todo",
            "sample_token",
        ];
        if MARKERS.iter().any(|m| blob.contains(m)) {
            return ValidityStatus::FalsePositive;
        }
        if matches!(
            candidate.rule_id.as_str(),
            "aws-access-key"
                | "github-pat"
                | "github-fine-grained-pat"
                | "github-oauth"
                | "private-key"
                | "stripe-secret"
                | "openai-api-key"
        ) {
            return ValidityStatus::Likely;
        }
        if candidate.pattern_strength >= 0.75 {
            return ValidityStatus::Suspicious;
        }
        ValidityStatus::Unknown
    }
}

/// Optional live checks. Only used when `--verify` is set.
/// Sends the candidate secret to the provider API from this machine.
pub struct LiveValidator {
    pub allow_network: bool,
}

impl Validator for LiveValidator {
    fn name(&self) -> &'static str {
        "live"
    }

    fn validate(&self, candidate: &Candidate) -> ValidityStatus {
        let base = SyntheticValidator.validate(candidate);
        if base == ValidityStatus::FalsePositive || !self.allow_network {
            return base;
        }
        match candidate.rule_id.as_str() {
            "github-pat" | "github-fine-grained-pat" | "github-oauth" => {
                verify_github(&candidate.raw).unwrap_or(base)
            }
            "stripe-secret" => verify_stripe(&candidate.raw).unwrap_or(base),
            _ => base,
        }
    }
}

fn verify_github(token: &str) -> Option<ValidityStatus> {
    let resp = ureq::get("https://api.github.com/user")
        .set("Authorization", &format!("Bearer {token}"))
        .set("User-Agent", "secgrep-verify")
        .set("Accept", "application/vnd.github+json")
        .timeout(std::time::Duration::from_secs(5))
        .call();
    match resp {
        Ok(r) if r.status() == 200 => Some(ValidityStatus::Verified),
        Ok(r) if r.status() == 401 || r.status() == 403 => Some(ValidityStatus::Suspicious),
        Ok(_) => Some(ValidityStatus::Unknown),
        Err(ureq::Error::Status(401 | 403, _)) => Some(ValidityStatus::Suspicious),
        Err(_) => None,
    }
}

fn verify_stripe(key: &str) -> Option<ValidityStatus> {
    let resp = ureq::get("https://api.stripe.com/v1/balance")
        .set("Authorization", &format!("Bearer {key}"))
        .timeout(std::time::Duration::from_secs(5))
        .call();
    match resp {
        Ok(r) if r.status() == 200 => Some(ValidityStatus::Verified),
        Ok(r) if r.status() == 401 => Some(ValidityStatus::Suspicious),
        Ok(_) => Some(ValidityStatus::Unknown),
        Err(ureq::Error::Status(401, _)) => Some(ValidityStatus::Suspicious),
        Err(_) => None,
    }
}

/// Format-only checks used in tests / offline verify dry-run.
pub fn format_plausible(candidate: &Candidate) -> bool {
    match candidate.rule_id.as_str() {
        "github-pat" => {
            candidate.raw.starts_with("ghp_") && candidate.raw.len() == 40
        }
        "stripe-secret" => {
            candidate.raw.starts_with("sk_test_") || candidate.raw.starts_with("sk_live_")
        }
        "aws-access-key" => {
            candidate.raw.starts_with("AKIA") && candidate.raw.len() == 20
        }
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Category, Severity};

    fn cand(raw: &str, line: &str, rule: &str) -> Candidate {
        Candidate {
            rule_id: rule.into(),
            file: "a.py".into(),
            line: 1,
            column: 1,
            category: Category::ApiKey,
            severity: Severity::High,
            pattern_strength: 0.9,
            description: "t".into(),
            raw: raw.into(),
            line_text: line.into(),
        }
    }

    #[test]
    fn example_marker_is_false_positive() {
        let v = SyntheticValidator;
        let key = format!("AKIA{}", "D7K3M2P9Q1W8X4YZ");
        let status = v.validate(&cand(&key, "# example key AKIA...", "aws-access-key"));
        assert_eq!(status, ValidityStatus::FalsePositive);
    }

    #[test]
    fn branded_key_is_likely_not_verified() {
        let v = SyntheticValidator;
        let key = format!("AKIA{}", "D7K3M2P9Q1W8X4YZ");
        let line = format!(r#"aws_key = "{key}""#);
        let status = v.validate(&cand(&key, &line, "aws-access-key"));
        assert_eq!(status, ValidityStatus::Likely);
        assert_ne!(status, ValidityStatus::Verified);
    }

    #[test]
    fn live_validator_without_network_stays_synthetic() {
        let v = LiveValidator {
            allow_network: false,
        };
        let key = format!("ghp_{}", "0123456789abcdefghijklmnopqrstuvwxyz");
        let status = v.validate(&cand(&key, "token=...", "github-pat"));
        assert_eq!(status, ValidityStatus::Likely);
    }

    #[test]
    fn format_plausible_github() {
        let key = format!("ghp_{}", "0123456789abcdefghijklmnopqrstuvwxyz");
        assert!(format_plausible(&cand(&key, "", "github-pat")));
    }
}
