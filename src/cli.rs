//! CLI surface.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::config::{Config, OutputFormat};
use crate::detect;
use crate::engine;
use crate::error::Error;
use crate::history;
use crate::hook;
use crate::report::Report;

#[derive(Parser, Debug)]
#[command(
    name = "secgrep",
    version,
    about = "SecretGuard: scan for hardcoded secrets, explain why, and tell you to rotate."
)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan a directory or file
    Scan {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        staged: bool,
        #[arg(long)]
        diff: Option<String>,
        /// text | json | sarif
        #[arg(long)]
        format: Option<String>,
        #[arg(long)]
        config: Option<PathBuf>,
        /// Optional live provider checks (GitHub PAT, Stripe). Off by default.
        #[arg(long)]
        verify: bool,
        /// Show full why/remediation for each finding
        #[arg(long)]
        verbose: bool,
        /// Emit GitHub Actions ::error annotations for blocked findings
        #[arg(long)]
        github_annotations: bool,
    },
    /// Scan Git history for secrets that may already have been "deleted"
    History {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        format: Option<String>,
        #[arg(long)]
        config: Option<PathBuf>,
        /// Only scan commits after this SHA (fast incremental history)
        #[arg(long)]
        since: Option<String>,
    },
    /// Scan the index, then run git commit only if policy passes
    Commit {
        #[arg(short = 'm', long)]
        message: Option<String>,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        extra: Vec<String>,
    },
    /// Install a local pre-commit hook (and optionally pre-push)
    InstallHook {
        #[arg(long)]
        pre_push: bool,
    },
    /// List built-in and custom rules
    Rules {
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

pub fn run() -> Result<i32, Error> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan {
            path,
            staged,
            diff,
            format,
            config,
            verify,
            verbose,
            github_annotations,
        } => run_scan(
            path,
            staged,
            diff,
            format,
            config,
            verify,
            verbose,
            github_annotations,
        ),
        Commands::History {
            path,
            format,
            config,
            since,
        } => run_history(path, format, config, since),
        Commands::Commit {
            message,
            config,
            extra,
        } => {
            let mut cfg = Config::load(config.as_deref())?;
            cfg.format = OutputFormat::Text;
            hook::commit(message.as_deref(), &extra, &cfg)
        }
        Commands::InstallHook { pre_push } => {
            let cwd = std::env::current_dir()?;
            let msg = hook::install_hook(&cwd, pre_push)?;
            print!("{msg}");
            Ok(0)
        }
        Commands::Rules { config } => {
            let cfg = Config::load(config.as_deref())?;
            let custom = engine::rules_from_config(&cfg);
            // rules_from_config already merges; list from detect with ignore + empty custom rebuilt:
            let summaries = detect::list_rule_summaries(&cfg.ignore_rules, &[]);
            let mut custom_only = Vec::new();
            for cr in &cfg.custom_rules {
                custom_only.push((
                    cr.id.clone(),
                    cr.severity.clone(),
                    format!("custom: {}", cr.regex),
                ));
            }
            println!("Built-in rules ({}):\n", summaries.len());
            for (id, sev, desc) in &summaries {
                if cfg.ignore_rules.iter().any(|x| x == id) {
                    continue;
                }
                println!("  {id:<28} {sev:<8} {desc}");
            }
            if !cfg.custom_rules.is_empty() {
                println!("\nCustom rules from config ({}):", cfg.custom_rules.len());
                for (id, sev, desc) in custom_only {
                    println!("  {id:<28} {sev:<8} {desc}");
                }
            }
            let _ = custom;
            Ok(0)
        }
    }
}

fn run_scan(
    path: PathBuf,
    staged: bool,
    diff: Option<String>,
    format: Option<String>,
    config: Option<PathBuf>,
    verify: bool,
    verbose: bool,
    github_annotations: bool,
) -> Result<i32, Error> {
    let mut cfg = Config::load(config.as_deref())?;
    if let Some(fmt) = format {
        cfg.format = OutputFormat::parse(&fmt)?;
    }
    if verify {
        cfg.verify = true;
        eprintln!(
            "secgrep: --verify enabled (live provider checks). Secrets may leave this machine."
        );
    }
    if staged && diff.is_some() {
        return Err(Error::new("use either --staged or --diff, not both"));
    }
    let (findings, stats) = if staged {
        engine::scan_staged(&path, &cfg)?
    } else if let Some(range) = diff {
        engine::scan_diff(&path, &range, &cfg)?
    } else {
        engine::scan_path(&path, &cfg)?
    };
    let report = Report::from_findings_with_stats(findings, cfg.min_confidence, Some(stats));
    if github_annotations {
        print!("{}", report.github_annotations(cfg.min_confidence));
    }
    let rendered = report
        .render(cfg.format, cfg.min_confidence, verbose)
        .map_err(|_| Error::new("failed to render report"))?;
    println!("{rendered}");
    Ok(report.exit_code())
}

fn run_history(
    path: PathBuf,
    format: Option<String>,
    config: Option<PathBuf>,
    since: Option<String>,
) -> Result<i32, Error> {
    let mut cfg = Config::load(config.as_deref())?;
    if let Some(fmt) = format {
        cfg.format = OutputFormat::parse(&fmt)?;
    }
    let (entries, current) = history::scan_history(&path, &cfg, since.as_deref())?;
    let report = history::HistoryReport::build(entries, current, cfg.min_confidence);
    match cfg.format {
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&report)
                .map_err(|_| Error::new("failed to render json"))?;
            println!("{json}");
        }
        OutputFormat::Sarif => {
            // History SARIF: reuse current findings + historical as notes
            let merged = report.current_findings.clone();
            let r = Report::from_findings(merged, cfg.min_confidence);
            println!("{}", r.render(OutputFormat::Sarif, cfg.min_confidence, false).unwrap_or_default());
        }
        OutputFormat::Text => {
            print!("{}", history::render_text(&report));
        }
    }
    Ok(report.exit_code())
}
