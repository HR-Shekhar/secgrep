//! Scan pipeline: files/git blobs → candidates → score → validate → policy.

use std::path::Path;
use std::time::Instant;

use rayon::prelude::*;

use crate::config::Config;
use crate::detect::{self, Rule};
use crate::error::Error;
use crate::finding::Finding;
use crate::git;
use crate::score;
use crate::validate::{LiveValidator, SyntheticValidator, Validator};
use crate::walk;

#[derive(Debug, Clone, Default)]
pub struct ScanStats {
    pub files_scanned: usize,
    pub duration_ms: u128,
    pub parallel: bool,
}

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
    analyze_with_rules(file, content, &rules, cfg.verify)
}

pub fn analyze_with_rules(
    file: &str,
    content: &str,
    rules: &[Rule],
    verify: bool,
) -> Vec<Finding> {
    let synthetic = SyntheticValidator;
    let live = LiveValidator {
        allow_network: verify,
    };
    let mut findings = Vec::new();
    for candidate in detect::find_candidates(file, content, rules) {
        let mut finding = score::score(&candidate);
        let status = if verify {
            live.validate(&candidate)
        } else {
            synthetic.validate(&candidate)
        };
        score::apply_validity(&mut finding, status);
        findings.push(finding);
    }
    dedupe(findings)
}

pub fn scan_path(path: &Path, cfg: &Config) -> Result<(Vec<Finding>, ScanStats), Error> {
    let started = Instant::now();
    let files = walk::collect_files(path, cfg);
    let files_scanned = files.len();
    let rules = rules_from_config(cfg);
    let verify = cfg.verify;

    // Parallelize across files — this is where Rust's speed shows on large trees.
    let findings: Vec<Finding> = files
        .par_iter()
        .flat_map(|file| analyze_with_rules(&file.relative, &file.text, &rules, verify))
        .collect();

    Ok((
        dedupe(findings),
        ScanStats {
            files_scanned,
            duration_ms: started.elapsed().as_millis(),
            parallel: true,
        },
    ))
}

pub fn scan_staged(path: &Path, cfg: &Config) -> Result<(Vec<Finding>, ScanStats), Error> {
    let started = Instant::now();
    let repo = git::repo_root(path)?;
    let blobs = git::staged_blobs(&repo, cfg)?;
    let files_scanned = blobs.len();
    let rules = rules_from_config(cfg);
    let verify = cfg.verify;
    let findings: Vec<Finding> = blobs
        .par_iter()
        .flat_map(|blob| analyze_with_rules(&blob.path, &blob.text, &rules, verify))
        .collect();
    Ok((
        dedupe(findings),
        ScanStats {
            files_scanned,
            duration_ms: started.elapsed().as_millis(),
            parallel: true,
        },
    ))
}

pub fn scan_diff(
    path: &Path,
    range: &str,
    cfg: &Config,
) -> Result<(Vec<Finding>, ScanStats), Error> {
    let started = Instant::now();
    let repo = git::repo_root(path)?;
    let blobs = git::diff_blobs(&repo, range, cfg)?;
    let files_scanned = blobs.len();
    let rules = rules_from_config(cfg);
    let verify = cfg.verify;
    let findings: Vec<Finding> = blobs
        .par_iter()
        .flat_map(|blob| analyze_with_rules(&blob.path, &blob.text, &rules, verify))
        .collect();
    Ok((
        dedupe(findings),
        ScanStats {
            files_scanned,
            duration_ms: started.elapsed().as_millis(),
            parallel: true,
        },
    ))
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
