//! Validity is stronger than a regex match. MVP never sends secrets to the network.

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
        if candidate.rule_id == "aws-access-key"
            || candidate.rule_id == "github-pat"
            || candidate.rule_id == "private-key"
        {
            return ValidityStatus::Likely;
        }
        if candidate.pattern_strength >= 0.75 {
            return ValidityStatus::Suspicious;
        }
        ValidityStatus::Unknown
    }
}

/// Adapter slot for a future provider check. Never wired to HTTP in this crate.
pub struct DisabledNetworkValidator;

impl Validator for DisabledNetworkValidator {
    fn name(&self) -> &'static str {
        "disabled-network"
    }

    fn validate(&self, candidate: &Candidate) -> ValidityStatus {
        SyntheticValidator.validate(candidate)
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
        let status = v.validate(&cand(
            &key,
            "# example key AKIA...",
            "aws-access-key",
        ));
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
}
