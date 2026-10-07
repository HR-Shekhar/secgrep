# Recommendations

Improvements that would not break the current program. Append-only polish list.

## Process

If code is ugly-but-correct, write it here instead of rewriting the working scanner mid-feature.

## Recorded during implementation

- Use the `ignore` crate so `secgrep scan .` respects `.gitignore` by default, with a `--no-ignore` audit mode.
- Replace `git` subprocess calls with `git2` for fewer process spawns and clearer error handling.
- Parallel file scanning with Rayon — **done** (`rayon` in `engine`).
- SARIF output — **done** (`--format sarif` + workflow upload).
- Optional live provider validation — **done** (`--verify` for GitHub PAT + Stripe).
- Expand the rule set — **done** for common cloud keys; keep growing from real misses only.
- Pre-push hook could batch multiple ref updates more carefully for force-pushes and deletions.
- Consider `zeroize` for temporary secret buffers if threat model requires it (usually not needed for a CLI that already redacts output).
- Windows: document that Git hooks need Git Bash / a POSIX `sh` to run the installed scripts.
- Optional classical ML for unknown high-entropy strings (never deep RNN as core) — Future only.
- Tiny HTML report generator — only if users ask; CLI remains primary UX.
