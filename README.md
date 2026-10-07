# secgrep (SecretGuard)

A developer-first secret scanner written in Rust.

It scans a repository for hardcoded secrets, explains why a hit looks real, hides the full value, and tells you to **rotate** the credential — not only delete the line.

## Why this exists

A hardcoded API key was committed, then removed from the current file. The key was still in Git history. Deleting a line does not undo a leak.

Existing tools (Gitleaks, TruffleHog, Semgrep Secrets, GitHub Secret Scanning) already detect many secrets. `secgrep` focuses on:

1. **Explainable confidence** — pattern + context + entropy + file path
2. **Historical exposure + rotate-first remediation**
3. **A commit wrapper, hooks, and CI that developers can actually run**
4. **Speed on large trees** — parallel file scanning (Rayon)

## Installation

### macOS / Linux (recommended)

```bash
curl -sSL https://raw.githubusercontent.com/HR-Shekhar/secgrep/main/install.sh | bash
```

This downloads the correct binary from the latest [GitHub Release](https://github.com/HR-Shekhar/secgrep/releases/latest) into `/usr/local/bin/secgrep`.

If you prefer not to pipe to bash, download the asset for your platform from the Releases page instead.

### Windows

1. Open [Releases](https://github.com/HR-Shekhar/secgrep/releases/latest).
2. Download `secgrep-windows-x86_64.exe`.
3. Rename it to `secgrep.exe` if you want, then add its folder to your PATH.
4. Run: `secgrep scan .`

### Unsigned binaries (expected for now)

Binaries are **not code-signed** yet.

- **Mac** may show “unidentified developer”. Fix: right-click → **Open**, or run  
  `xattr -d com.apple.quarantine secgrep`
- **Windows** SmartScreen may show “unrecognized app”. Fix: **More info** → **Run anyway**

### Build from source

```bash
cargo build --release
# binary: target/release/secgrep  (Windows: target\release\secgrep.exe)
```

How maintainers publish new binaries: [docs/release.md](docs/release.md).

## Usage

Six main commands:

```bash
secgrep scan .                 # scan the project
secgrep scan --staged          # scan only what is about to be committed
secgrep history .              # secrets still in Git history? → ROTATE
secgrep commit -m "message"    # scan staged, then git commit if clean
secgrep install-hook           # pre-commit hook (local convenience)
secgrep rules                  # list detection rules
```

Also useful:

```bash
secgrep scan --diff HEAD~1..HEAD
secgrep scan . --format json
secgrep scan . --format sarif
secgrep scan . --verbose
secgrep scan . --github-annotations
secgrep scan . --verify
secgrep history . --since <commitsha>
secgrep install-hook --pre-push
```

Exit codes: `0` clean · `1` policy fail · `2` tool error.

## What we detect (built-in)

AWS access/secret keys, GitHub PAT/OAuth, Slack, Stripe, OpenAI-style keys, Google API keys, Twilio, SendGrid, npm tokens, JWTs, private keys, DB URLs, Bearer headers, generic secret assignments.

Custom rules go in `secgrep.toml`:

```toml
[[rules]]
id = "acme-internal"
regex = "ACME_[A-Z0-9]{32}"
category = "api_key"
severity = "high"
```

## Speed

Directory and staged/diff scans process files **in parallel**. Text output shows:

```text
Scan: 120 file(s) · 45 ms · parallel
```

History supports `--since <sha>` so large repos can scan only new commits.

## Configuration

`secgrep.toml`:

```toml
ignore_paths = ["testdata", "tests", "target", ".git", "node_modules", "docs"]
min_confidence = 0.65
format = "text"
# verify = false   # never enable in shared config unless you intend live checks
```

## Git hooks (local convenience)

```bash
./target/release/secgrep install-hook
./target/release/secgrep install-hook --pre-push
```

Bypass: `git commit --no-verify` / `git push --no-verify`. Hooks are reminders, not the final gate.

## Server-side hook (self-hosted)

On github.com you cannot install server hooks. On self-hosted Git, use:

[`deploy/pre-receive.sh`](deploy/pre-receive.sh)

That rejects pushes the developer cannot skip with `--no-verify`.

## GitHub Actions

[`.github/workflows/secretguard.yml`](.github/workflows/secretguard.yml) runs tests, scans the tree, scans the PR diff, emits annotations, and uploads SARIF.

**A red check does not block merge** until you require the `secretguard` status check in branch protection / rulesets.

## Demo

- Planted flaws: `secgrep scan testdata/corpus`
- Judge script: [docs/judge-demo.md](docs/judge-demo.md)
- Hooks/CI detail: [docs/hooks-and-ci.md](docs/hooks-and-ci.md)

## Roadmap vs older limitations

| Old limit | Status |
|-----------|--------|
| Small rule set | Expanded (Stripe, OpenAI, Google, Twilio, …) + `secgrep rules` + custom TOML rules |
| No live validation | Optional `--verify` (GitHub PAT, Stripe), default off |
| Hooks bypassable | Still true locally; added self-hosted `pre-receive` + required CI docs |
| Slow history | `--since` incremental history + parallel file scans |
| No GitHub UX | SARIF upload + `--github-annotations` |

Still not trying to replace GitHub Push Protection or TruffleHog’s full verifier catalog.

## License

MIT
