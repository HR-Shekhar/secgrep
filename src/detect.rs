//! Pattern-based detectors. Regex is necessary and insufficient — scoring happens later.

use regex::Regex;

use crate::finding::{Candidate, Category, Severity};

pub struct Rule {
    pub id: String,
    pub category: Category,
    pub severity: Severity,
    pub regex: Regex,
    pub group: usize,
    pub pattern_strength: f64,
    pub description: String,
    pub multiline: bool,
}

pub fn builtin_rules() -> Vec<Rule> {
    vec![
        rule(
            "aws-access-key",
            Category::ApiKey,
            Severity::Critical,
            r"\b(AKIA[0-9A-Z]{16})\b",
            1,
            0.9,
            "AWS access key id (AKIA...)",
            false,
        ),
        rule(
            "github-pat",
            Category::AccessToken,
            Severity::Critical,
            r"\b(ghp_[A-Za-z0-9]{36})\b",
            1,
            0.9,
            "GitHub personal access token",
            false,
        ),
        rule(
            "github-fine-grained-pat",
            Category::AccessToken,
            Severity::Critical,
            r"\b(github_pat_[A-Za-z0-9_]{20,})\b",
            1,
            0.9,
            "GitHub fine-grained personal access token",
            false,
        ),
        rule(
            "slack-token",
            Category::AccessToken,
            Severity::High,
            r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b",
            1,
            0.85,
            "Slack token",
            false,
        ),
        rule(
            "jwt",
            Category::Jwt,
            Severity::High,
            r"\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b",
            1,
            0.7,
            "JWT-like three-part token",
            false,
        ),
        rule(
            "private-key",
            Category::PrivateKey,
            Severity::Critical,
            r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
            0,
            0.95,
            "PEM/OpenSSH private key block",
            true,
        ),
        rule(
            "connection-string",
            Category::ConnectionString,
            Severity::High,
            r#"\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis)://[^\s"'<>]+)"#,
            1,
            0.8,
            "Database connection string with credentials",
            false,
        ),
        rule(
            "authorization-bearer",
            Category::AuthorizationHeader,
            Severity::High,
            r#"(?i)authorization\s*[:=]\s*['"]?bearer\s+([A-Za-z0-9._+=/-]{12,})"#,
            1,
            0.75,
            "Authorization Bearer token",
            false,
        ),
        rule(
            "generic-secret-assignment",
            Category::GenericSecret,
            Severity::Medium,
            r#"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password)\s*[=:]\s*['"]([^'"]{16,})['"]"#,
            1,
            0.45,
            "Quoted assignment to a secret-like variable",
            false,
        ),
    ]
}

fn rule(
    id: &str,
    category: Category,
    severity: Severity,
    pattern: &str,
    group: usize,
    pattern_strength: f64,
    description: &str,
    multiline: bool,
) -> Rule {
    Rule {
        id: id.to_string(),
        category,
        severity,
        regex: Regex::new(pattern).unwrap_or_else(|e| panic!("builtin regex {id}: {e}")),
        group,
        pattern_strength,
        description: description.to_string(),
        multiline,
    }
}

pub fn compile_custom(
    id: &str,
    pattern: &str,
    category: Category,
    severity: Severity,
) -> Result<Rule, String> {
    let regex = Regex::new(pattern).map_err(|_| format!("invalid regex in custom rule {id}"))?;
    Ok(Rule {
        id: id.to_string(),
        category,
        severity,
        regex,
        group: 0,
        pattern_strength: 0.7,
        description: format!("custom rule {id}"),
        multiline: pattern.contains("[\\s\\S]") || pattern.contains("(?s)"),
    })
}

pub fn active_rules(ignore_rules: &[String], custom: &[Rule]) -> Vec<Rule> {
    let mut rules: Vec<Rule> = builtin_rules()
        .into_iter()
        .filter(|r| !ignore_rules.iter().any(|id| id == &r.id))
        .collect();
    for rule in custom {
        if ignore_rules.iter().any(|id| id == &rule.id) {
            continue;
        }
        rules.push(rule.clone_rule());
    }
    rules
}

impl Rule {
    fn clone_rule(&self) -> Rule {
        Rule {
            id: self.id.clone(),
            category: self.category,
            severity: self.severity,
            regex: self.regex.clone(),
            group: self.group,
            pattern_strength: self.pattern_strength,
            description: self.description.clone(),
            multiline: self.multiline,
        }
    }
}

pub fn find_candidates(file: &str, content: &str, rules: &[Rule]) -> Vec<Candidate> {
    let mut out = Vec::new();
    for rule in rules {
        if rule.multiline {
            for caps in rule.regex.captures_iter(content) {
                let Some(mat) = caps.get(rule.group) else {
                    continue;
                };
                let (line, column) = offset_to_line_col(content, mat.start());
                let line_text = line_at(content, line);
                out.push(Candidate {
                    rule_id: rule.id.clone(),
                    file: file.to_string(),
                    line,
                    column,
                    category: rule.category,
                    severity: rule.severity,
                    pattern_strength: rule.pattern_strength,
                    description: rule.description.clone(),
                    raw: mat.as_str().to_string(),
                    line_text,
                });
            }
        } else {
            for (idx, line_text) in content.lines().enumerate() {
                let line = idx + 1;
                for caps in rule.regex.captures_iter(line_text) {
                    let Some(mat) = caps.get(rule.group) else {
                        continue;
                    };
                    out.push(Candidate {
                        rule_id: rule.id.clone(),
                        file: file.to_string(),
                        line,
                        column: mat.start() + 1,
                        category: rule.category,
                        severity: rule.severity,
                        pattern_strength: rule.pattern_strength,
                        description: rule.description.clone(),
                        raw: mat.as_str().to_string(),
                        line_text: line_text.to_string(),
                    });
                }
            }
        }
    }
    out
}

fn offset_to_line_col(text: &str, offset: usize) -> (usize, usize) {
    let prefix = &text[..offset.min(text.len())];
    let line = prefix.bytes().filter(|&b| b == b'\n').count() + 1;
    let col = prefix
        .rsplit('\n')
        .next()
        .map(|s| s.chars().count())
        .unwrap_or(0)
        + 1;
    (line, col)
}

fn line_at(text: &str, line: usize) -> String {
    text.lines()
        .nth(line.saturating_sub(1))
        .unwrap_or("")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_aws_access_key() {
        let rules = builtin_rules();
        // Split so the repo source itself does not contain a contiguous fake key.
        let key = format!("AKIA{}", "D7K3M2P9Q1W8X4YZ");
        let content = format!(r#"key = "{key}""#);
        let hits = find_candidates("a.py", &content, &rules);
        assert!(hits.iter().any(|h| h.rule_id == "aws-access-key"));
    }

    #[test]
    fn detects_generic_assignment() {
        let rules = builtin_rules();
        let value = format!("{}{}", "abcdefghijkl", "mnopqrstuvwxyz");
        let content = format!(r#"API_KEY = "{value}""#);
        let hits = find_candidates("a.py", &content, &rules);
        assert!(hits.iter().any(|h| h.rule_id == "generic-secret-assignment"));
    }
}
