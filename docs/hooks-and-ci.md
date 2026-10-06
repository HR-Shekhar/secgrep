# Git hooks and GitHub Actions — how to use them

## Git hooks (on your laptop)

### What a hook is

A hook is a script Git runs at a specific moment. Hooks live in:

```text
.git/hooks/
```

`secgrep install-hook` writes:

| Hook | When it runs | What it runs |
|------|--------------|--------------|
| `pre-commit` | Before a commit is created | `secgrep scan --staged` |
| `pre-push` (optional) | Before a push leaves your machine | `secgrep scan --diff` over the commits being pushed |

### Install

```bash
cargo build --release
./target/release/secgrep install-hook
./target/release/secgrep install-hook --pre-push
```

### Bypass (be honest)

```bash
git commit --no-verify
git push --no-verify
```

Local hooks are convenience. They are not enforcement.

### Alternative: commit wrapper

```bash
secgrep commit -m "message"
```

This scans staged files, then runs `git commit` only if the scan is clean.

## GitHub Actions (on GitHub’s servers)

### What the workflow does

File: `.github/workflows/secretguard.yml`

1. Checks out the repository (full history)
2. Runs tests
3. Builds `secgrep`
4. Scans the tree with `secgrep scan .`
5. On pull requests, scans the PR diff

If `secgrep` exits `1`, the job fails and the PR shows a red check named **secretguard**.

### Make the check block merges

1. Repository **Settings**
2. **Rules → Rulesets** (or classic branch protection)
3. Enable **Require status checks to pass**
4. Select **`secretguard`**

Until that is configured, people can still merge a red PR.

### Why this is stronger than a local hook

The Action runs on GitHub. Developers cannot skip it with `--no-verify`. Combined with a **required** status check, it is the real merge gate.
