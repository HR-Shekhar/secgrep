//! Local intercepts: `secgrep commit` and Git hooks.
//! Both are convenience. They can be bypassed. CI + required checks are the real gate.

use std::fs;
use std::path::Path;
use std::process::Command;

use crate::config::Config;
use crate::engine;
use crate::error::Error;
use crate::git;
use crate::report::Report;

pub fn install_hook(start: &Path, pre_push: bool) -> Result<String, Error> {
    let repo = git::repo_root(start)?;
    let hook_dir = repo.join(".git").join("hooks");
    fs::create_dir_all(&hook_dir)?;
    let exe = std::env::current_exe()
        .map_err(|_| Error::new("could not locate secgrep executable"))?;
    let exe_str = exe.to_string_lossy().replace('\\', "/");

    let mut messages = Vec::new();

    let pre_commit = hook_dir.join("pre-commit");
    let pre_commit_script = format!(
        "#!/bin/sh\n# Installed by `secgrep install-hook`.\n# Bypass: git commit --no-verify\nexec \"{exe_str}\" scan --staged\n"
    );
    fs::write(&pre_commit, pre_commit_script)?;
    set_executable(&pre_commit)?;
    messages.push(format!("installed pre-commit hook at {}", pre_commit.display()));

    if pre_push {
        let pre_push_path = hook_dir.join("pre-push");
        let pre_push_script = format!(
            r#"#!/bin/sh
# Installed by `secgrep install-hook --pre-push`.
# Bypass: git push --no-verify
# Git feeds ref updates on stdin: local_ref local_sha remote_ref remote_sha
SECGREP="{exe_str}"
zero=0000000000000000000000000000000000000000
while read local_ref local_sha remote_ref remote_sha
do
  if [ "$local_sha" = "$zero" ]; then
    continue
  fi
  if [ "$remote_sha" = "$zero" ]; then
    "$SECGREP" scan . || exit 1
  else
    "$SECGREP" scan --diff "${{remote_sha}}..${{local_sha}}" || exit 1
  fi
done
exit 0
"#
        );
        fs::write(&pre_push_path, pre_push_script)?;
        set_executable(&pre_push_path)?;
        messages.push(format!("installed pre-push hook at {}", pre_push_path.display()));
    }

    messages.push(
        "these are convenience layers. --no-verify skips them; use a required CI check as the real gate."
            .into(),
    );
    Ok(messages.join("\n") + "\n")
}

fn set_executable(_path: &Path) -> Result<(), Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(_path, perms)?;
    }
    Ok(())
}

pub fn commit(message: Option<&str>, extra: &[String], cfg: &Config) -> Result<i32, Error> {
    let cwd = std::env::current_dir()?;
    let (findings, stats) = engine::scan_staged(&cwd, cfg)?;
    let report = Report::from_findings_with_stats(findings, cfg.min_confidence, Some(stats));
    let rendered = report
        .render(cfg.format, cfg.min_confidence, false)
        .map_err(|_| Error::new("failed to render report"))?;
    if report.blocked_count > 0 {
        print!("{rendered}");
        eprintln!(
            "secgrep: commit blocked. Rotate the credential; do not only delete the line."
        );
        return Ok(1);
    }

    let mut cmd = Command::new("git");
    cmd.arg("commit");
    if let Some(msg) = message {
        cmd.arg("-m").arg(msg);
    }
    cmd.args(extra);
    let status = cmd
        .status()
        .map_err(|_| Error::new("failed to execute git commit"))?;
    Ok(status.code().unwrap_or(2))
}
