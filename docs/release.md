# Public releases — how to ship binaries

This project ships ready-to-run binaries via GitHub Actions. You do **not** need to build Windows/Linux/Mac binaries on your laptop.

## What gets published

When you push a tag like `v0.2.0`, [`.github/workflows/release.yml`](../.github/workflows/release.yml) builds and attaches:

| Asset | Platform |
|-------|----------|
| `secgrep-darwin-arm64` | Mac Apple Silicon (M1–M4) |
| `secgrep-darwin-x86_64` | Mac Intel |
| `secgrep-linux-x86_64` | Linux 64-bit |
| `secgrep-windows-x86_64.exe` | Windows 64-bit |

Users install with [`install.sh`](../install.sh) (Mac/Linux) or download the `.exe` from Releases (Windows).

## Before every release

1. Set `version` in `Cargo.toml` (must match the tag, without the leading `v`).
2. Locally:

```bash
cargo test
cargo build --release
./target/release/secgrep scan .
```

3. Commit and push to `main`.

## Create a release

Current package version is **0.2.0**, so the first public tag should be:

```bash
git add .
git commit -m "add release workflow, installer and license"
git push

git tag v0.2.0
git push origin v0.2.0
```

Then open **GitHub → Actions → Release** and wait until all 4 jobs are green.

## Check the result

Repo page → right side **Releases** → `v0.2.0` should list 4 files.

## Test like a user (Mac/Linux)

```bash
curl -sSL https://raw.githubusercontent.com/HR-Shekhar/secgrep/main/install.sh | bash
secgrep scan .
```

Windows: download `secgrep-windows-x86_64.exe` from Releases, rename to `secgrep.exe` if you want, put it on PATH, run `secgrep scan .`.

## New version later

1. Bump `version` in `Cargo.toml` (e.g. `0.2.1`).
2. Commit and push.
3. `git tag v0.2.1 && git push origin v0.2.1`
4. `latest` download links update automatically.

## Redo a bad release

```bash
git tag -d v0.2.0
git push origin :refs/tags/v0.2.0
```

Delete the GitHub Release in the UI, fix the code, then tag again.

## Unsigned binaries

Binaries are not code-signed yet.

- **Mac:** right-click → Open, or `xattr -d com.apple.quarantine secgrep`
- **Windows:** SmartScreen → More info → Run anyway

## Related files

- [`.github/workflows/release.yml`](../.github/workflows/release.yml) — build + upload
- [`install.sh`](../install.sh) — Mac/Linux installer
- [`LICENSE`](../LICENSE) — MIT
- [`.github/workflows/secretguard.yml`](../.github/workflows/secretguard.yml) — CI secret scan (separate from releases)
