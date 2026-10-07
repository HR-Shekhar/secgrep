# Demo script (fake secrets only)

Never use real production credentials.

## 1. Get a binary

**From a public release (Mac/Linux):**

```bash
curl -sSL https://raw.githubusercontent.com/HR-Shekhar/secgrep/main/install.sh | bash
```

**Or build from source:**

```bash
cargo build --release
```

Windows: download `secgrep-windows-x86_64.exe` from [Releases](https://github.com/HR-Shekhar/secgrep/releases/latest), or use `target\release\secgrep.exe` after building.

Maintainer release steps: [release.md](release.md).

## 2. Scan planted flaws

```bash
./target/release/secgrep scan testdata/corpus
```

Expect exit code **1**, redacted previews, and **ROTATE** guidance. The full fake key must not appear.

## 3. Clean scan of source

```bash
./target/release/secgrep scan src
```

Expect exit code **0**.

## 4. Block a commit

In a throwaway git repo:

```bash
# Use a fake key shaped like AKIA + 16 chars. Do not use a real credential.
python -c "open('leak.py','w').write('aws_access_key_id = \"AKIA'+'D7K3M2P9Q1W8X4YZ'+'\"\\n')"
git add leak.py
secgrep commit -m "should fail"
```

Expect exit code **1** and no new commit.

## 5. Install hooks

```bash
secgrep install-hook
secgrep install-hook --pre-push
```

Then `git commit` runs `secgrep scan --staged`. Bypass with `git commit --no-verify` (document this as a weakness).

## 6. History: rotate, don’t just delete

```bash
# Commit A: introduce fake key
# Commit B: delete the line
# Commit C: clean tree
secgrep history .
```

Expect:

- Current tree: not present
- Historical exposure: YES
- Recommended action: ROTATE

## 7. GitHub Action

Push a PR with a planted fake secret. The `secretguard` job fails.

To block merge: mark the `secretguard` check as **required** in branch protection / rulesets.

A red check alone does not block merge.
