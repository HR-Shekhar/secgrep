# Architecture

```
CLI (clap)
   ↓
scanner (walk / staged / diff / history)
   ↓
detectors (regex rules)
   ↓
scoring (pattern + context + entropy + file)
   ↓
validator (synthetic only — no network)
   ↓
policy (min_confidence)
   ↓
reporter (text / JSON, redacted)
   ↓
Git hooks / GitHub Actions
```

## Modules

| Module | Role |
|--------|------|
| `cli` | Commands and flags |
| `walk` | Directory walk, binary skip |
| `detect` | Regex rules → candidates |
| `score` | Multi-signal confidence |
| `validate` | Placeholder / synthetic status |
| `redact` | Hide secrets; SHA-256 fingerprint |
| `remediate` | Rotate-first guidance |
| `git` | Subprocess Git helpers |
| `history` | First/last seen in history |
| `hook` | `commit` wrapper + hook install |
| `report` | Text and JSON output |
| `config` | `secgrep.toml` |

## Safety

- Findings never store a `raw` secret field for output
- JSON and text use `redacted_preview` only
- `verify=true` in config is refused (no live API calls)
- Symlinks are not followed
- Huge files and binaries are skipped
