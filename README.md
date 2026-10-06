# secgrep (SecretGuard)

A developer-first secret scanner written in Rust.

It scans a repository for hardcoded secrets, explains why a hit looks real, hides the full value, and tells you to **rotate** the credential — not only delete the line.

## Why this exists

A hardcoded API key was committed, then removed from the current file. The key was still in Git history. Deleting a line does not undo a leak.

Existing tools (Gitleaks, TruffleHog, Semgrep Secrets, GitHub Secret Scanning) already detect many secrets. `secgrep` focuses on:

1. **Explainable confidence** — pattern + context + entropy + file path
2. **Historical exposure + rotate-first remediation**
3. **A commit wrapper and hooks developers can actually run**

It does **not** send secrets to the network. “Verified” in this tool means multi-signal scoring + synthetic placeholder checks, not a live AWS/GitHub API call.

## Install

```bash
cargo build --release
# binary: target/release/secgrep  (Windows: target\release\secgrep.exe)
```

Optional:

```bash
cargo install --path .
```

## Commands

```bash
secgrep scan .
secgrep scan --staged
secgrep scan --diff HEAD~1..HEAD
secgrep history .
secgrep commit -m "message"
secgrep install-hook
secgrep install-hook --pre-push
```

Exit codes:

| Code | Meaning |
|------|---------|
| 0 | Clean (no blocking findings) |
| 1 | Policy failure — block commit / fail CI |
| 2 | Tool error (not a git repo, bad config, git missing) |

Formats:

```bash
secgrep scan . --format text
secgrep scan . --format json
```

## Configuration

Optional `secgrep.toml` in the project root:

```toml
ignore_paths = ["testdata", "target", ".git", "node_modules"]
min_confidence = 0.65
format = "text"
```

## Git hooks (local convenience)

Hooks live in `.git/hooks`. They run on **your machine** and can be skipped.

```bash
# After building:
cargo build --release

# Install pre-commit (scans staged files before every git commit)
./target/release/secgrep install-hook

# Also install pre-push (last local stop before code leaves the laptop)
./target/release/secgrep install-hook --pre-push
```

Or use the wrapper instead of `git commit`:

```bash
secgrep commit -m "your message"
```

**Honest limits:**

- `git commit --no-verify` skips the pre-commit hook
- `git push --no-verify` skips the pre-push hook
- Calling `git commit` directly skips `secgrep commit`
- There is **no** hook for `git add`

Local hooks are reminders. They are not the final security boundary.

## GitHub Actions (CI)

This repo includes [`.github/workflows/secretguard.yml`](.github/workflows/secretguard.yml).

On every pull request / push it:

1. runs `cargo test`
2. builds `secgrep`
3. runs `secgrep scan .`
4. on PRs, also scans the PR diff

### Important: a red X does not block merge by itself

A failing GitHub Action only reports failure. Merge is blocked **only if** the repository requires that check.

To enforce:

1. Open the repository on GitHub
2. **Settings → Rules → Rulesets** (or **Branches → Branch protection**)
3. Require status checks to pass before merging
4. Add the check named **`secretguard`** (the job name in the workflow)

Official docs:

- [Require status checks to pass before merging](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)
- [Push protection](https://docs.github.com/en/code-security/concepts/secret-security/push-protection) (GitHub’s own platform check — separate from this tool)

### Self-hosted server hook (optional, docs only)

On GitHub.com you cannot install server-side hooks. On self-hosted Git (GitHub Enterprise Server, GitLab, Gitea), a `pre-receive` hook can run the same binary:

```bash
secgrep scan --diff "$oldrev..$newrev"
```

and reject the push if exit code is 1. That is real enforcement because the developer does not control the server.

## Demo (fake secrets only)

See [docs/demo.md](docs/demo.md). Never use real production credentials in tests.

## Architecture

See [docs/architecture.md](docs/architecture.md).

## Limitations

- Small rule set compared to Gitleaks / TruffleHog
- No live provider validation (by design in v1)
- Local hooks are bypassable
- History scan uses `git log -p` and can be slow on huge repos
- Does not replace GitHub Push Protection

## License

MIT
