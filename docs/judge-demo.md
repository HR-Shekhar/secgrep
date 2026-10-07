# How to show this to judges (no custom UI needed)

A terminal demo is the right choice for this product. Judges expect a security CLI, not a dashboard.

## Optional opener: public install (15s)

If a GitHub Release already exists:

```bash
curl -sSL https://raw.githubusercontent.com/HR-Shekhar/secgrep/main/install.sh | bash
secgrep --version
```

Shows this is a real downloadable tool, not only a repo of source. See [release.md](release.md).

## 5-minute script

1. **Problem (30s)** — Hardcoded key committed, then deleted. History still has it. Must rotate.
2. **Scan corpus (60s)**  
   `secgrep scan testdata/corpus`  
   (or `cargo run --release -- scan testdata/corpus`)  
   Point at: readable banner, BLOCK vs info, redacted preview, ROTATE, scan timing (parallel).
3. **False positive (30s)** — Show a YOUR_API_KEY / docs example that does **not** block.
4. **Commit block (60s)** — Plant a fake key, `secgrep commit -m "x"` fails; no commit created.
5. **History (60s)** — Leak → delete → `secgrep history .` → historical YES + ROTATE.
6. **CI (30s)** — Show green Action on clean PR; say: mark `secretguard` required to block merge. Show SARIF upload / annotations if available.

## Do you need a custom UI?

**For judges: no.** A fast, readable CLI is stronger than a half-built web UI.

**For users: not required for v1.** Optional later:
- SARIF in GitHub Security tab (already supported)
- PR line annotations (already supported via `--github-annotations`)
- A tiny web report only if customers ask

Ship the CLI. Treat UI as future polish, not the core.
