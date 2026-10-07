//! Git helpers via subprocess. We shell out so the Git model stays visible.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::config::Config;
use crate::error::Error;
use crate::walk::text_from_bytes;

pub fn repo_root(start: &Path) -> Result<PathBuf, Error> {
    let mut dir = if start.is_file() {
        start.parent().unwrap_or(start).to_path_buf()
    } else {
        start.to_path_buf()
    };
    if dir.is_relative() {
        dir = std::env::current_dir()?.join(dir);
    }
    let mut cur = dir;
    loop {
        if cur.join(".git").exists() {
            return Ok(cur);
        }
        if !cur.pop() {
            return Err(Error::new(
                "not a git repository (required for --staged, --diff, history, commit, install-hook)",
            ));
        }
    }
}

pub fn git(repo: &Path, args: &[&str]) -> Result<Vec<u8>, Error> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .map_err(|_| Error::new("failed to execute git (is it installed and on PATH?)"))?;
    if !output.status.success() {
        return Err(Error::new("git command failed"));
    }
    Ok(output.stdout)
}

pub struct NamedBlob {
    pub path: String,
    pub text: String,
}

fn path_ignored(path: &str, cfg: &Config) -> bool {
    let normalized = path.replace('\\', "/");
    cfg.ignore_paths.iter().any(|p| {
        normalized == *p
            || normalized.starts_with(&format!("{p}/"))
            || normalized.contains(&format!("/{p}/"))
            || normalized.ends_with(&format!("/{p}"))
    })
}

pub fn staged_blobs(repo: &Path, cfg: &Config) -> Result<Vec<NamedBlob>, Error> {
    let stdout = git(
        repo,
        &[
            "diff",
            "--cached",
            "--name-only",
            "--diff-filter=ACMR",
            "-z",
        ],
    )?;
    let names = split_z(&stdout);
    let mut blobs = Vec::new();
    for name in names {
        if name.is_empty() || path_ignored(&name, cfg) {
            continue;
        }
        let spec = format!(":{name}");
        match git(repo, &["show", &spec]) {
            Ok(bytes) => {
                if let Some(text) = text_from_bytes(&bytes, cfg) {
                    blobs.push(NamedBlob { path: name, text });
                }
            }
            Err(_) => continue,
        }
    }
    Ok(blobs)
}

pub fn diff_blobs(repo: &Path, range: &str, cfg: &Config) -> Result<Vec<NamedBlob>, Error> {
    let (from, to) = parse_range(range)?;
    let stdout = git(
        repo,
        &[
            "diff",
            "--name-only",
            "--diff-filter=ACMR",
            "-z",
            &from,
            &to,
        ],
    )?;
    let names = split_z(&stdout);
    let mut blobs = Vec::new();
    for name in names {
        if name.is_empty() || path_ignored(&name, cfg) {
            continue;
        }
        let spec = format!("{to}:{name}");
        match git(repo, &["show", &spec]) {
            Ok(bytes) => {
                if let Some(text) = text_from_bytes(&bytes, cfg) {
                    blobs.push(NamedBlob { path: name, text });
                }
            }
            Err(_) => continue,
        }
    }
    Ok(blobs)
}

pub fn parse_range(range: &str) -> Result<(String, String), Error> {
    let Some((a, b)) = range.split_once("..") else {
        return Err(Error::new(
            "diff range must look like FROM..TO (example: HEAD~1..HEAD)",
        ));
    };
    let from = if a.is_empty() { "HEAD" } else { a };
    let to = if b.is_empty() { "HEAD" } else { b };
    Ok((from.to_string(), to.to_string()))
}

pub fn log_patch(repo: &Path, since_commit: Option<&str>) -> Result<String, Error> {
    let mut args: Vec<String> = vec![
        "log".into(),
        "--reverse".into(),
        "--pretty=format:COMMIT:%H".into(),
        "--patch".into(),
        "--unified=0".into(),
    ];
    if let Some(since) = since_commit {
        // Incremental: only commits after this SHA (much faster on large repos).
        args.push(format!("{since}..HEAD"));
    } else {
        args.insert(2, "--all".into());
    }
    let str_args: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let bytes = git(repo, &str_args)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn split_z(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).replace('\\', "/"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_diff_range() {
        assert_eq!(
            parse_range("HEAD~1..HEAD").unwrap(),
            ("HEAD~1".into(), "HEAD".into())
        );
        assert_eq!(
            parse_range("..HEAD").unwrap(),
            ("HEAD".into(), "HEAD".into())
        );
    }
}
