//! Human, JSON, and SARIF reporters. Never includes raw secrets.

use serde::Serialize;
use serde_json::{json, Value};

use crate::config::OutputFormat;
use crate::engine::ScanStats;
use crate::finding::Finding;

#[derive(Debug, Serialize)]
pub struct Report {
    pub status: &'static str,
    pub finding_count: usize,
    pub blocked_count: usize,
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<ScanStatsDto>,
}

#[derive(Debug, Serialize, Clone)]
pub struct ScanStatsDto {
    pub files_scanned: usize,
    pub duration_ms: u128,
    pub parallel: bool,
}

impl From<&ScanStats> for ScanStatsDto {
    fn from(s: &ScanStats) -> Self {
        Self {
            files_scanned: s.files_scanned,
            duration_ms: s.duration_ms,
            parallel: s.parallel,
        }
    }
}

impl Report {
    pub fn from_findings(findings: Vec<Finding>, min_confidence: f64) -> Self {
        Self::from_findings_with_stats(findings, min_confidence, None)
    }

    pub fn from_findings_with_stats(
        findings: Vec<Finding>,
        min_confidence: f64,
        stats: Option<ScanStats>,
    ) -> Self {
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
            stats: stats.as_ref().map(ScanStatsDto::from),
        }
    }

    pub fn render(
        &self,
        format: OutputFormat,
        min_confidence: f64,
        verbose: bool,
    ) -> Result<String, serde_json::Error> {
        match format {
            OutputFormat::Json => serde_json::to_string_pretty(self),
            OutputFormat::Text => Ok(render_text(self, min_confidence, verbose)),
            OutputFormat::Sarif => Ok(render_sarif(self, min_confidence)),
        }
    }

    pub fn exit_code(&self) -> i32 {
        if self.blocked_count > 0 {
            1
        } else {
            0
        }
    }

    /// GitHub Actions workflow commands for PR inline annotations.
    pub fn github_annotations(&self, min_confidence: f64) -> String {
        let mut out = String::new();
        for f in &self.findings {
            if !f.should_block(min_confidence) {
                continue;
            }
            let msg = format!(
                "{} ({}) preview={} — ROTATE; do not only delete",
                f.category.title(),
                f.rule_id,
                f.redacted_preview
            );
            // Escape newlines/% for workflow commands
            let msg = msg.replace('%', "%25").replace('\n', "%0A");
            out.push_str(&format!(
                "::error file={},line={},col={}::{}\n",
                f.file, f.line, f.column, msg
            ));
        }
        out
    }
}

fn render_text(report: &Report, min_confidence: f64, verbose: bool) -> String {
    let mut out = String::new();
    out.push_str("╔══════════════════════════════════════╗\n");
    out.push_str("║           secgrep / SecretGuard      ║\n");
    out.push_str("╚══════════════════════════════════════╝\n");

    if let Some(stats) = &report.stats {
        out.push_str(&format!(
            "Scan: {} file(s) · {} ms · {}\n",
            stats.files_scanned,
            stats.duration_ms,
            if stats.parallel {
                "parallel"
            } else {
                "sequential"
            }
        ));
    }

    out.push_str(&format!(
        "Result: {} · {} finding(s) · {} blocked (threshold {:.0}%)\n\n",
        report.status.to_uppercase(),
        report.finding_count,
        report.blocked_count,
        min_confidence * 100.0
    ));

    if report.findings.is_empty() {
        out.push_str("✓ No secret candidates found.\n");
        return out;
    }

    // Show blocking findings first
    let mut ordered: Vec<&Finding> = report.findings.iter().collect();
    ordered.sort_by(|a, b| {
        let ab = a.should_block(min_confidence);
        let bb = b.should_block(min_confidence);
        bb.cmp(&ab)
            .then(
                b.confidence
                    .partial_cmp(&a.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
    });

    for (i, f) in ordered.iter().enumerate() {
        let blocked = f.should_block(min_confidence);
        let mark = if blocked { "BLOCK" } else { "info " };
        out.push_str(&format!("── [{:}] #{i} ─────────────────────────\n", mark));
        out.push_str(&format!("  {}:{}\n", f.file, f.line));
        out.push_str(&format!(
            "  {} · {} · {:.0}% · {}\n",
            f.category.title(),
            f.rule_id,
            f.confidence * 100.0,
            f.status.as_str()
        ));
        out.push_str(&format!("  preview: {}\n", f.redacted_preview));
        if verbose {
            out.push_str("  why:\n");
            for reason in &f.why {
                out.push_str(&format!("    • {reason}\n"));
            }
            out.push_str("  next steps:\n");
            for step in f.remediation.iter().take(3) {
                out.push_str(&format!("    • {step}\n"));
            }
        } else {
            let tip = f
                .remediation
                .first()
                .map(|s| s.as_str())
                .unwrap_or("ROTATE the credential");
            out.push_str(&format!("  → {tip}\n"));
            if !f.why.is_empty() {
                out.push_str(&format!("  why: {}\n", f.why[0]));
            }
        }
        out.push('\n');
    }

    if report.blocked_count > 0 {
        out.push_str("Action required: ROTATE credentials. Deleting the line is not enough.\n");
        out.push_str("Tip: run with --verbose for full rationale, or `secgrep history .` for Git exposure.\n");
    } else {
        out.push_str("No findings crossed the block threshold.\n");
    }
    out
}

fn render_sarif(report: &Report, min_confidence: f64) -> String {
    let mut results = Vec::new();
    let mut rules_map: Vec<Value> = Vec::new();
    let mut seen_rules = std::collections::HashSet::new();

    for f in &report.findings {
        if !seen_rules.contains(&f.rule_id) {
            seen_rules.insert(f.rule_id.clone());
            rules_map.push(json!({
                "id": f.rule_id,
                "name": f.rule_id,
                "shortDescription": { "text": f.category.title() },
                "fullDescription": { "text": format!("{} — rotate, do not only delete", f.category.title()) },
                "defaultConfiguration": {
                    "level": if f.severity.as_str() == "critical" { "error" } else { "warning" }
                }
            }));
        }
        let level = if f.should_block(min_confidence) {
            "error"
        } else {
            "note"
        };
        results.push(json!({
            "ruleId": f.rule_id,
            "level": level,
            "message": {
                "text": format!(
                    "{} ({:.0}%) preview={} — ROTATE credential",
                    f.category.title(),
                    f.confidence * 100.0,
                    f.redacted_preview
                )
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": { "uri": f.file.replace('\\', "/") },
                    "region": {
                        "startLine": f.line.max(1),
                        "startColumn": f.column.max(1)
                    }
                }
            }]
        }));
    }

    let doc = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "secgrep",
                    "informationUri": "https://github.com/secgrep/secgrep",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": rules_map
                }
            },
            "results": results
        }]
    });
    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into())
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
        let json = report.render(OutputFormat::Json, 0.65, false).unwrap();
        assert!(!json.contains(&secret));
        assert!(!json.contains("\"raw\""));
    }

    #[test]
    fn text_is_compact_and_has_banner() {
        let report = Report::from_findings(vec![sample("AKIA************X4YZ")], 0.65);
        let text = report.render(OutputFormat::Text, 0.65, false).unwrap();
        assert!(text.contains("secgrep"));
        assert!(text.contains("BLOCK"));
        assert!(text.contains("ROTATE"));
        assert!(!text.contains("AKIAD7K3"));
    }

    #[test]
    fn sarif_has_results_without_raw_secret() {
        let secret = format!("AKIA{}", "D7K3M2P9Q1W8X4YZ");
        let report = Report::from_findings(vec![sample("AKIA************X4YZ")], 0.65);
        let sarif = report.render(OutputFormat::Sarif, 0.65, false).unwrap();
        assert!(sarif.contains("\"version\": \"2.1.0\""));
        assert!(sarif.contains("aws-access-key"));
        assert!(!sarif.contains(&secret));
    }

    #[test]
    fn github_annotations_use_workflow_commands() {
        let report = Report::from_findings(vec![sample("AKIA************X4YZ")], 0.65);
        let ann = report.github_annotations(0.65);
        assert!(ann.contains("::error file=config.py,line=14"));
        let secret = format!("AKIA{}", "D7K3M2P9Q1W8X4YZ");
        assert!(!ann.contains(&secret));
    }
}
