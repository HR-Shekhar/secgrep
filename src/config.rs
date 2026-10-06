//! TOML configuration. Small surface: not 100 knobs.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::Error;
use crate::finding::{Category, Severity};

const DEFAULT_MIN_CONFIDENCE: f64 = 0.65;
const DEFAULT_MAX_FILE_BYTES: u64 = 1_048_576;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    Text,
    Json,
}

impl OutputFormat {
    pub fn parse(s: &str) -> Result<Self, Error> {
        match s {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            other => Err(Error::new(format!(
                "unknown format '{other}' (use text or json)"
            ))),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CustomRule {
    pub id: String,
    pub regex: String,
    #[serde(default = "default_category")]
    pub category: String,
    #[serde(default = "default_severity")]
    pub severity: String,
}

fn default_category() -> String {
    "generic_secret".into()
}

fn default_severity() -> String {
    "high".into()
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct FileConfig {
    #[serde(default)]
    pub ignore_paths: Vec<String>,
    #[serde(default)]
    pub ignore_rules: Vec<String>,
    pub min_confidence: Option<f64>,
    pub max_file_bytes: Option<u64>,
    pub format: Option<String>,
    #[serde(default)]
    pub verify: bool,
    #[serde(default)]
    pub rules: Vec<CustomRule>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub ignore_paths: Vec<String>,
    pub ignore_rules: Vec<String>,
    pub min_confidence: f64,
    pub max_file_bytes: u64,
    pub format: OutputFormat,
    pub verify: bool,
    pub custom_rules: Vec<CustomRule>,
}

impl Config {
    pub fn defaults() -> Self {
        Self {
            ignore_paths: default_ignore_paths(),
            ignore_rules: Vec::new(),
            min_confidence: DEFAULT_MIN_CONFIDENCE,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            format: OutputFormat::Text,
            verify: false,
            custom_rules: Vec::new(),
        }
    }

    pub fn load(explicit: Option<&Path>) -> Result<Self, Error> {
        let mut cfg = Self::defaults();
        let path = match explicit {
            Some(p) => Some(p.to_path_buf()),
            None => find_config_file(),
        };
        if let Some(path) = path {
            let raw = fs::read_to_string(&path)
                .map_err(|_| Error::new(format!("could not read config {}", path.display())))?;
            let parsed: FileConfig = toml::from_str(&raw)
                .map_err(|_| Error::new("malformed secgrep.toml (check keys and types)"))?;
            apply_file(&mut cfg, parsed)?;
        }
        if cfg.verify {
            return Err(Error::new(
                "verify=true is refused in this build: live provider validation is off by design",
            ));
        }
        Ok(cfg)
    }
}

fn apply_file(cfg: &mut Config, parsed: FileConfig) -> Result<(), Error> {
    if !parsed.ignore_paths.is_empty() {
        for p in parsed.ignore_paths {
            if !cfg.ignore_paths.iter().any(|x| x == &p) {
                cfg.ignore_paths.push(p);
            }
        }
    }
    cfg.ignore_rules = parsed.ignore_rules;
    if let Some(c) = parsed.min_confidence {
        if !(0.0..=1.0).contains(&c) {
            return Err(Error::new("min_confidence must be between 0 and 1"));
        }
        cfg.min_confidence = c;
    }
    if let Some(n) = parsed.max_file_bytes {
        cfg.max_file_bytes = n;
    }
    if let Some(fmt) = parsed.format {
        cfg.format = OutputFormat::parse(&fmt)?;
    }
    cfg.verify = parsed.verify;
    for rule in &parsed.rules {
        if Category::parse_config(&rule.category).is_none() {
            return Err(Error::new(format!(
                "unknown category '{}' in custom rule {}",
                rule.category, rule.id
            )));
        }
        if Severity::parse_config(&rule.severity).is_none() {
            return Err(Error::new(format!(
                "unknown severity '{}' in custom rule {}",
                rule.severity, rule.id
            )));
        }
    }
    cfg.custom_rules = parsed.rules;
    Ok(())
}

fn find_config_file() -> Option<PathBuf> {
    let cwd = std::env::current_dir().ok()?;
    let here = cwd.join("secgrep.toml");
    if here.is_file() {
        return Some(here);
    }
    None
}

pub fn default_ignore_paths() -> Vec<String> {
    vec![
        ".git".into(),
        "target".into(),
        "node_modules".into(),
        "dist".into(),
        "build".into(),
        "vendor".into(),
        ".venv".into(),
        "__pycache__".into(),
        "testdata".into(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_confidence() {
        let mut cfg = Config::defaults();
        let parsed = FileConfig {
            min_confidence: Some(1.5),
            ..FileConfig::default()
        };
        assert!(apply_file(&mut cfg, parsed).is_err());
    }

    #[test]
    fn parses_minimal_toml() {
        let parsed: FileConfig = toml::from_str(
            r#"
ignore_paths = ["vendor"]
min_confidence = 0.8
"#,
        )
        .unwrap();
        let mut cfg = Config::defaults();
        apply_file(&mut cfg, parsed).unwrap();
        assert_eq!(cfg.min_confidence, 0.8);
        assert!(cfg.ignore_paths.iter().any(|p| p == "vendor"));
    }
}
