//! CLI surface.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::config::{Config, OutputFormat};
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
        /// Path to scan (file or directory)
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Scan only the Git index (what the next commit would contain)
        #[arg(long)]
        staged: bool,
        /// Scan files changed in a Git range, e.g. HEAD~1..HEAD
        #[arg(long)]
        diff: Option<String>,
        /// text or json
        #[arg(long)]
        format: Option<String>,
        /// Path to secgrep.toml
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Scan Git history for secrets that may already have been "deleted"
    History {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        format: Option<String>,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Scan the index, then run git commit only if policy passes
    Commit {
        #[arg(short = 'm', long)]
        message: Option<String>,
        #[arg(long)]
        config: Option<PathBuf>,
        /// Extra arguments forwarded to git commit
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        extra: Vec<String>,
    },
    /// Install a local pre-commit hook (and optionally pre-push)
    InstallHook {
        /// Also install a pre-push hook
        #[arg(long)]
        pre_push: bool,
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
        } => run_scan(path, staged, diff, format, config),
        Commands::History {
            path,
            format,
            config,
        } => run_history(path, format, config),
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
    }
}

fn run_scan(
    path: PathBuf,
    staged: bool,
    diff: Option<String>,
    format: Option<String>,
    config: Option<PathBuf>,
) -> Result<i32, Error> {
    let mut cfg = Config::load(config.as_deref())?;
    if let Some(fmt) = format {
        cfg.format = OutputFormat::parse(&fmt)?;
    }
    if staged && diff.is_some() {
        return Err(Error::new("use either --staged or --diff, not both"));
    }
    let findings = if staged {
        engine::scan_staged(&path, &cfg)?
    } else if let Some(range) = diff {
        engine::scan_diff(&path, &range, &cfg)?
    } else {
        engine::scan_path(&path, &cfg)?
    };
    let report = Report::from_findings(findings, cfg.min_confidence);
    let rendered = report
        .render(cfg.format, cfg.min_confidence)
        .map_err(|_| Error::new("failed to render report"))?;
    println!("{rendered}");
    Ok(report.exit_code())
}

fn run_history(
    path: PathBuf,
    format: Option<String>,
    config: Option<PathBuf>,
) -> Result<i32, Error> {
    let mut cfg = Config::load(config.as_deref())?;
    if let Some(fmt) = format {
        cfg.format = OutputFormat::parse(&fmt)?;
    }
    let (entries, current) = history::scan_history(&path, &cfg)?;
    let report = history::HistoryReport::build(entries, current, cfg.min_confidence);
    match cfg.format {
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&report)
                .map_err(|_| Error::new("failed to render json"))?;
            println!("{json}");
        }
        OutputFormat::Text => {
            print!("{}", history::render_text(&report));
        }
    }
    Ok(report.exit_code())
}
