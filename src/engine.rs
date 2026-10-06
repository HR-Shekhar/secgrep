//! Scan pipeline: files/git blobs → candidates → score → validate → policy.

use std::path::Path;

use crate::config::Config;
use crate::detect::{self, Rule};
use crate::error::Error;
use crate::finding::Finding;
use crate::git;
use crate::score;
use crate::validate::{SyntheticValidator, Validator};
use crate::walk;

pub fn rules_from_config(cfg: &Config) -> Vec<Rule> {
    let mut custom = Vec::new();
    for cr in &cfg.custom_rules {
        let category = crate::finding::Category::parse_config(&cr.category)
            .unwrap_or(crate::finding::Category::GenericSecret);
        let severity = crate::finding::Severity::parse_config(&cr.severity)
            .unwrap_or(crate::finding::Severity::High);
        match detect::compile_custom(&cr.id, &cr.regex, category, severity) {
            Ok(rule) => custom.push(rule),
            Err(_) => continue,
        }
    }
    detect::active_rules(&cfg.ignore_rules, &custom)
}

pub fn analyze_text(file: &str, content: &str, cfg: &Config) -> Vec<Finding> {
    let rules = rules_from_config(cfg);
    analyze_with_rules(file, content, &rules)
}

pub fn analyze_with_rules(file: &str, content: &str, rules: &[Rule]) -> Vec<Finding> {
    let validator = SyntheticValidator;
    let mut findings = Vec::new();
    for candidate in detect::find_candidates(file, content, rules) {
        let mut finding = score::score(&candidate);
        let status = validator.validate(&candidate);
        score::apply_validity(&mut finding, status);
        findings.push(finding);
    }
    dedupe(findings)
}

pub fn scan_path(path: &Path, cfg: &Config) -> Result<Vec<Finding>, Error> {
    let files = walk::collect_files(path, cfg);
    let rules = rules_from_config(cfg);
    let mut findings = Vec::new();
    for file in files {
        findings.extend(analyze_with_rules(&file.relative, &file.text, &rules));
    }
    Ok(dedupe(findings))
}

pub fn scan_staged(path: &Path, cfg: &Config) -> Result<Vec<Finding>, Error> {
    let repo = git::repo_root(path)?;
    let blobs = git::staged_blobs(&repo, cfg)?;
    let rules = rules_from_config(cfg);
    let mut findings = Vec::new();
    for blob in blobs {
        findings.extend(analyze_with_rules(&blob.path, &blob.text, &rules));
    }
    Ok(dedupe(findings))
}

pub fn scan_diff(path: &Path, range: &str, cfg: &Config) -> Result<Vec<Finding>, Error> {
    let repo = git::repo_root(path)?;
    let blobs = git::diff_blobs(&repo, range, cfg)?;
    let rules = rules_from_config(cfg);
    let mut findings = Vec::new();
    for blob in blobs {
        findings.extend(analyze_with_rules(&blob.path, &blob.text, &rules));
    }
    Ok(dedupe(findings))
}

fn dedupe(mut findings: Vec<Finding>) -> Vec<Finding> {
    findings.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.fingerprint.cmp(&b.fingerprint))
            .then(
                b.confidence
                    .partial_cmp(&a.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
    });
    findings.dedup_by(|a, b| {
        a.file == b.file && a.line == b.line && a.fingerprint == b.fingerprint
    });
    findings
}
