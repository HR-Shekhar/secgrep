//! Human and JSON reporters. JSON never includes raw secrets.

use serde::Serialize;

use crate::config::OutputFormat;
use crate::finding::Finding;

#[derive(Debug, Serialize)]
pub struct Report {
    pub status: &'static str,
    pub finding_count: usize,
    pub blocked_count: usize,
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn from_findings(findings: Vec<Finding>, min_confidence: f64) -> Self {
        let blocked_count = findings
            .iter()
            .filter(|f| f.should_block(min_confidence))
            .count();
        let status = if blocked_count > 0 { "failed" } else { "clean" };
        Self {
            status,
            finding_count: findings.len(),
            blocked_count,
            findings,
        }
    }

    pub fn render(
        &self,
        format: OutputFormat,
        min_confidence: f64,
    ) -> Result<String, serde_json::Error> {
        match format {
            OutputFormat::Json => serde_json::to_string_pretty(self),
            OutputFormat::Text => Ok(render_text(self, min_confidence)),
        }
    }

    pub fn exit_code(&self) -> i32 {
        if self.blocked_count > 0 {
            1
        } else {
            0
        }
    }
}

fn render_text(report: &Report, min_confidence: f64) -> String {
    let mut out = String::new();
    if report.findings.is_empty() {
        out.push_str("No secret candidates found.\n");
        return out;
    }

    for f in &report.findings {
        let blocked = f.should_block(min_confidence);
        out.push_str(&format!("{}:{}\n", f.file, f.line));
        out.push_str(&format!("{}\n", f.category.title()));
        out.push_str(&format!("rule: {}\n", f.rule_id));
        out.push_str(&format!("severity: {}\n", f.severity.as_str()));
        out.push_str(&format!("confidence: {:.0}%\n", f.confidence * 100.0));
        out.push_str(&format!("status: {}\n", f.status.as_str()));
        out.push_str(&format!("preview: {}\n", f.redacted_preview));
        out.push_str(&format!(
            "policy: {}\n",
            if blocked { "BLOCK" } else { "do not block" }
        ));
        out.push_str("Why we believe this:\n");
        for reason in &f.why {
            out.push_str(&format!("  - {reason}\n"));
        }
        out.push_str("Recommended action:\n");
        for step in &f.remediation {
            out.push_str(&format!("  - {step}\n"));
        }
        out.push('\n');
    }

    out.push_str(&format!(
        "summary: {} finding(s), {} blocked (threshold {:.0}%)\n",
        report.finding_count,
        report.blocked_count,
        min_confidence * 100.0
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Category, Severity, Signals, ValidityStatus};

    fn sample(preview: &str) -> Finding {
        Finding {
            rule_id: "aws-access-key".into(),
            file: "config.py".into(),
            line: 14,
            column: 1,
            category: Category::ApiKey,
            redacted_preview: preview.into(),
            confidence: 0.9,
            severity: Severity::Critical,
            detector: "t".into(),
            status: ValidityStatus::Likely,
            why: vec!["recognized AWS access key id".into()],
            remediation: vec!["ROTATE".into()],
            signals: Signals {
                pattern: 0.9,
                context: 0.1,
                entropy: 0.1,
                entropy_bits: 4.0,
                file: 0.0,
                validity: 0.0,
                notes: vec![],
            },
            fingerprint: "abc".into(),
        }
    }

    #[test]
    fn json_does_not_include_a_raw_secret_field() {
        let secret = format!("AKIA{}", "D7K3M2P9Q1W8X4YZ");
        let report = Report::from_findings(vec![sample("AKIA************X4YZ")], 0.65);
        let json = report.render(OutputFormat::Json, 0.65).unwrap();
        assert!(!json.contains(&secret));
        assert!(!json.contains("\"raw\""));
        assert!(!json.contains("matched_text"));
    }
}
