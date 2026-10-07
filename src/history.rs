//! Historical exposure: first/last seen in diffs, plus current-tree presence.

use std::collections::HashMap;
use std::path::Path;

use serde::Serialize;

use crate::config::{Config, OutputFormat};
use crate::engine;
use crate::error::Error;
use crate::finding::Finding;
use crate::git;
use crate::report::Report;

#[derive(Debug, Clone, Serialize)]
pub struct HistoryEntry {
    pub category: String,
    pub rule_id: String,
    pub redacted_preview: String,
    pub fingerprint: String,
    pub first_seen: String,
    pub last_seen: String,
    pub commit_count: usize,
    pub files: Vec<String>,
    pub current_tree: &'static str,
    pub historical_exposure: &'static str,
    pub recommended_action: String,
    pub remediation: Vec<String>,
}

struct Acc {
    sample: Finding,
    first: String,
    last: String,
    commits: Vec<String>,
    files: Vec<String>,
}

pub fn scan_history(
    path: &Path,
    cfg: &Config,
    since_commit: Option<&str>,
) -> Result<(Vec<HistoryEntry>, Vec<Finding>), Error> {
    let repo = git::repo_root(path)?;
    let patch = git::log_patch(&repo, since_commit)?;
    let mut by_fp: HashMap<String, Acc> = HashMap::new();

    let mut commit = String::new();
    let mut file = String::new();
    for line in patch.lines() {
        if let Some(hash) = line.strip_prefix("COMMIT:") {
            commit = hash.trim().to_string();
            file.clear();
            continue;
        }
        if let Some(rest) = line.strip_prefix("+++ b/") {
            file = rest.trim().to_string();
            continue;
        }
        if line.starts_with("+++ /dev/null") {
            file.clear();
            continue;
        }
        if !line.starts_with('+') || line.starts_with("+++") {
            continue;
        }
        if commit.is_empty() || file.is_empty() {
            continue;
        }
        let added = &line[1..];
        let findings = engine::analyze_text(&file, added, cfg);
        for f in findings {
            let acc = by_fp.entry(f.fingerprint.clone()).or_insert_with(|| Acc {
                sample: f.clone(),
                first: commit.clone(),
                last: commit.clone(),
                commits: Vec::new(),
                files: Vec::new(),
            });
            if !acc.commits.iter().any(|c| c == &commit) {
                acc.commits.push(commit.clone());
            }
            acc.last = commit.clone();
            if !acc.files.iter().any(|p| p == &file) {
                acc.files.push(file.clone());
            }
        }
    }

    let (current, _) = engine::scan_path(path, cfg)?;
    let current_fps: Vec<String> = current.iter().map(|f| f.fingerprint.clone()).collect();

    let mut entries: Vec<HistoryEntry> = by_fp
        .into_values()
        .map(|acc| {
            let in_tree = current_fps.iter().any(|fp| fp == &acc.sample.fingerprint);
            HistoryEntry {
                category: acc.sample.category.title().to_string(),
                rule_id: acc.sample.rule_id.clone(),
                redacted_preview: acc.sample.redacted_preview.clone(),
                fingerprint: acc.sample.fingerprint.clone(),
                first_seen: acc.first,
                last_seen: acc.last,
                commit_count: acc.commits.len(),
                files: acc.files,
                current_tree: if in_tree { "present" } else { "not present" },
                historical_exposure: "YES",
                recommended_action: "ROTATE credential — deleting from current files is not enough"
                    .into(),
                remediation: acc.sample.remediation.clone(),
            }
        })
        .collect();
    entries.sort_by(|a, b| a.rule_id.cmp(&b.rule_id).then(a.first_seen.cmp(&b.first_seen)));
    Ok((entries, current))
}

#[derive(Serialize)]
pub struct HistoryReport {
    pub status: &'static str,
    pub historical_count: usize,
    pub current_finding_count: usize,
    pub entries: Vec<HistoryEntry>,
    pub current_findings: Vec<Finding>,
}

impl HistoryReport {
    pub fn build(entries: Vec<HistoryEntry>, current: Vec<Finding>, min_confidence: f64) -> Self {
        let current_blocked = current
            .iter()
            .filter(|f| f.should_block(min_confidence))
            .count();
        let status = if current_blocked > 0 {
            "failed"
        } else if !entries.is_empty() {
            "clean_tree_history_exposed"
        } else {
            "clean"
        };
        Self {
            status,
            historical_count: entries.len(),
            current_finding_count: current.len(),
            entries,
            current_findings: current,
        }
    }

    pub fn exit_code(&self) -> i32 {
        if self.status == "failed" {
            1
        } else {
            0
        }
    }
}

pub fn render_text(report: &HistoryReport) -> String {
    let mut out = String::new();
    out.push_str("╔══════════════════════════════════════╗\n");
    out.push_str("║     secgrep history · rotate check   ║\n");
    out.push_str("╚══════════════════════════════════════╝\n");
    out.push_str(&format!(
        "Status: {} · historical: {} · current findings: {}\n\n",
        report.status, report.historical_count, report.current_finding_count
    ));
    if report.entries.is_empty() && report.current_findings.is_empty() {
        out.push_str("✓ No historical or current secret candidates found.\n");
        return out;
    }
    for (i, e) in report.entries.iter().enumerate() {
        out.push_str(&format!("── history #{} ───────────────────────\n", i + 1));
        out.push_str(&format!("  {} ({})\n", e.category, e.rule_id));
        out.push_str(&format!("  preview: {}\n", e.redacted_preview));
        out.push_str(&format!("  first seen:  {}\n", e.first_seen));
        out.push_str(&format!("  last seen:   {}\n", e.last_seen));
        out.push_str(&format!("  commits:     {}\n", e.commit_count));
        out.push_str(&format!("  current tree: {}\n", e.current_tree));
        out.push_str(&format!(
            "  historical:  {}\n",
            e.historical_exposure
        ));
        out.push_str(&format!("  → {}\n\n", e.recommended_action));
    }
    if !report.current_findings.is_empty() {
        out.push_str("── current tree ───────────────────────\n");
        let current = Report::from_findings(report.current_findings.clone(), 0.65);
        out.push_str(
            &current
                .render(OutputFormat::Text, 0.65, false)
                .unwrap_or_default(),
        );
    }
    out
}
