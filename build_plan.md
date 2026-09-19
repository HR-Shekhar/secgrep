# secgrep — finite build plan

SecretGuard / `secgrep` is a developer-first secret scanner. This file is the contract. When Part 7 is done, the project is done. Do not add a Part 8.

We learn while building. Ugly-but-correct code stays; polish goes in [recommendations.md](recommendations.md). Questions happen at the end of a part (or every few teaching turns), not after every message.

---

## The incident we are solving

A fintech team hardcoded an API key. It was committed, then “fixed” by deleting the line. The key was still in Git history. Attackers do not need the current tree.

**Solve:** scan before commit and before merge, block on high-confidence findings, cut false positives, and teach **rotate — do not only delete**.

Existing tools (Gitleaks, TruffleHog, Semgrep Secrets, GitHub Push Protection) already detect well. We will not pretend to beat them on rule count or live API verification. We ship a **small, explainable, offline-first Rust CLI** that a company can run everywhere without sending code or secrets to us.

---

## Approach (read this before writing product code)

### What we build

A single Rust **package** (`secgrep`) with one **binary crate**. Later we may split scan logic into `src/lib.rs` so tests can call it without the CLI. That split is optional until Part 2 needs it.

Pipeline (every scan goes through this; no extra services):

```
path / staged blobs / history patches
        ↓
   walk + skip (.git, binaries, huge files, ignore_paths)
        ↓
   detectors (small regex rule set — not 700 rules)
        ↓
   scorer (pattern + context + entropy + file type)
        ↓
   validator (synthetic only: placeholders → false_positive; NO network)
        ↓
   policy (confidence threshold)
        ↓
   redacted reporter (text or JSON)
        ↓
   exit 0 / 1 / 2
```

**Verified finding (our meaning):** high-confidence + not classified false_positive. We do **not** call AWS/GitHub to see if a key is still live. That is TruffleHog’s job and it sends secrets off-box. Enterprise “verified” in v1 means **multi-signal + synthetic validity**, not a live HTTP check. A `Validator` trait exists so a future opt-in adapter can be added without a rewrite; v1 never turns it on.

### How we block commits and merges

Layered. Anything that runs on the developer's machine is a reminder; only something running on a server is enforcement.

| Layer | Command / place | Strength |
|---|---|---|
| Convenience | `secgrep commit -m "..."` | Easy for humans; skippable (`git commit` directly) |
| Convenience | `secgrep install-hook` (pre-commit) | Catches normal `git commit`; bypass `git commit --no-verify` |
| Convenience | `secgrep install-hook --pre-push` | Last local stop before code leaves the laptop; bypass `git push --no-verify` |
| Real gate | GitHub Action + **required** status check | Failing Action alone does not block merge. A ruleset/branch protection rule must require the check |
| Real gate (self-hosted, docs only) | `pre-receive` on the Git server | Rejects the push itself; developer cannot bypass. Not installable on github.com |

We implement the first four. The fifth is documentation because it reuses the same binary.

There is **no hook for `git add`** — Git does not provide one, and `add` only marks files locally. Commit and push are the moments worth guarding. `.gitignore` is not a security control: it does nothing for a key pasted inside a tracked file like `config.py`.

### How we cut false positives

Not “high entropy = secret.” Score is the sum of documented signals:

- pattern strength (AWS `AKIA…` is stronger than `password = "..."`)
- context (variable name `api_key` vs placeholder `YOUR_API_KEY`)
- Shannon entropy (one signal, can vote down *or* up)
- file path (`.env` up; `README.md`, `.min.js`, tests down)
- synthetic validity (example/fake/xxxx → do not block)

### How we teach rotate-don’t-delete

`secgrep history .` walks `git log -p` (subprocess, not git2). For each fingerprint (SHA-256 of the secret, never printed raw):

- first seen commit
- last seen in a diff
- present in current tree? yes/no
- historical exposure: YES
- recommended action: ROTATE

Demo repo (fake secrets only): commit A introduces a key, B deletes it, C is clean. History still says YES.

### How we stay safe as a scanner

- Never print the full secret in text or JSON
- Never put secrets in error messages
- Never send candidates to the network
- Do not follow symlinks
- Skip huge files and binaries
- Planted keys in tests/docs are **fake** (`AKIA` + obviously non-prod material, or `EXAMPLE` markers)

### What we will not build (v1)

LLM, GitHub App, PR review bot, database, website, VS Code extension, Kubernetes, live provider validation, archive bombs, Semgrep-style dataflow, 700 detectors.

### Stack (keep it small)

`clap` (CLI), `walkdir`, `regex`, `serde`/`serde_json`, `toml`, `sha2`. Git via `git` subprocess so we learn real Git. `git2` can go in recommendations.md later.

### How we work

1. One part at a time. Do not start Part N+1 until Part N’s “done when” is true.
2. Smallest code that meets the done line. Then learn the Rust that appeared.
3. Production nits that do not break behavior → [recommendations.md](recommendations.md), not a rewrite.
4. After a part: a few conceptual questions + what to type next.

---

## Frozen CLI (v1)

```
secgrep scan [PATH] [--staged] [--diff FROM..TO] [--format text|json] [--config FILE]
secgrep history [PATH] [--format text|json]
secgrep commit -m "message"
secgrep install-hook
```

Exit codes: `0` clean, `1` policy failure (block commit/CI), `2` tool error (not a repo, bad config, git missing).

Default config file: `secgrep.toml` in the current directory. Few keys only: `ignore_paths`, `ignore_rules`, `min_confidence`, `format`. No 100 knobs.

---

## Parts

### Part 0 — Cargo + Rust we need (status: done enough)

Package `secgrep` exists. You have used `String`, `&str`, and a borrow (`show(&file)`).

**Done when:** `cargo run` builds. (Playground in `main.rs` will be replaced in Part 1.)

---

### Part 1 — CLI skeleton

**Learn:** `clap` derive, subcommands, `PathBuf`, process args after `--`.

**Build:** `secgrep scan [PATH]` (default `.`). Print `scanning <path>`. `--help` works. No walk, no regex.

**Done when:**

```
cargo run -- scan .
cargo run -- --help
```

prints the path / shows `scan`. Exit 0.

---

### Part 2 — First real scan

**Learn:** `walkdir`, skip `.git` / `target` / `node_modules`, binary = NUL or non-UTF-8, line numbers, `Result` when a file cannot be read (skip + continue, do not crash).

**Build:** Recurse. Match a tiny builtin set only:

1. AWS access key id: `AKIA` + 16 `A–Z0–9`
2. PEM private key begin/end block
3. Quoted assignment to `api_key` / `secret` / `password` / `token` (generic)

Print `file:line`, rule name, severity. Still print a **redacted** preview (start redaction here so we never leak in the terminal).

Add `testdata/` with **fake** positives and a binary file. Default ignore `testdata` when scanning `.` so this repo’s CI stays green; tests pass an explicit path.

**Done when:** `cargo run -- scan testdata/corpus` exits 1 and lists hits. Scanning a folder of clean files exits 0.

---

### Part 3 — Finding model + secret safety

**Learn:** `struct`, `enum`, `serde` (later JSON uses the same type), why we store `fingerprint` (SHA-256) and never `raw` on the public struct.

**Build:** `Finding { rule_id, file, line, column, category, redacted_preview, confidence, severity, why, remediation, fingerprint }`. One test: stdout/JSON must not contain the planted full secret.

**Done when:** that test exists and passes. Normal output has no complete secret.

---

### Part 4 — False positives (enterprise requirement)

**Learn:** Shannon entropy as bits/byte; it is a clue, not a proof.

**Build:** Documented score = pattern + context + entropy + file. Synthetic validator marks example/placeholder/xxxx as `false_positive` (do not block). Threshold default `0.65`.

Cover these cases in tests (fake data): real-looking key; placeholder; UUID; hex hash; docs example; `os.getenv` / `process.env`; minified path; low-entropy dummy.

**Done when:** obvious fakes do not block; branded fake AWS-shaped key in source does block.

---

### Part 5 — Git intercept (commit must be scanned)

**Learn:** working tree vs index vs `HEAD`; `git diff --cached`; hooks live in `.git/hooks`; hooks are bypassable; there is no hook for `git add`.

**Build:**

- `scan --staged` — blobs from the index (`git show :path`)
- `scan --diff FROM..TO` — files changed in that range
- `secgrep commit -m` — staged scan, then `git commit` only if policy passes
- `secgrep install-hook` — writes `pre-commit` that runs `scan --staged`
- `secgrep install-hook --pre-push` — writes `pre-push` that runs `scan --diff` over the commits being pushed, so a `--no-verify` commit is still caught before the code leaves the machine

**Done when:** a planted fake key in the index makes `secgrep commit -m "x"` exit 1 and does not create a commit; with the pre-push hook installed, a commit made with `--no-verify` is blocked at push time.

---

### Part 6 — History + rotate (enterprise requirement)

**Learn:** deleting a line adds a new commit; old commits remain; `git log -p`.

**Build:** `secgrep history .` as specified above. Remediation text always starts with ROTATE, then remove from source, env/secret manager (env is not always enough in production), check history, check systems.

**Done when:** a tiny demo history (A leak → B delete → C clean) reports historical exposure YES and current tree not present.

---

### Part 7 — Config, JSON, CI, docs (then stop)

**Learn:** TOML; GitHub Actions `pull_request`; required status checks (official GitHub docs).

**Build:** `secgrep.toml`, `--format json` (`{ "status": "failed"|"clean", "findings": [...] }`), `.github/workflows/secretguard.yml` (checkout `fetch-depth: 0`, `cargo test`, `secgrep scan .`). README: install, usage, hook, CI, **Action fail ≠ merge block**, self-hosted server-side option (below), limitations vs Gitleaks/TruffleHog. Short `docs/architecture.md` and `docs/demo.md` (fake keys only).

**Done when:** JSON is stable enough for CI; workflow file exists; README states the required-check rule; `cargo test` is green.

---

## Server-side enforcement (documentation, not v1 code)

Local hooks can always be skipped (`--no-verify`, or just not installing them). The only checks a developer cannot bypass run on a machine they do not control.

- **github.com:** you cannot install server-side hooks. The real gate is the Action plus a ruleset that marks the check **required**. GitHub's own push protection is a separate backstop that only covers well-known token formats.
- **Self-hosted (GitHub Enterprise Server, GitLab, Gitea):** a `pre-receive` hook on the server can run the same `secgrep` binary against the incoming commits and reject the push outright. No new code — the README explains how to install the binary on the server and call `secgrep scan --diff`.

This is why history scanning and rotation guidance exist: by the time any layer is skipped, the secret is already recorded, and rotating the credential is the only real fix.

---

## Mapping to the problem statement

| Requirement | Where |
|---|---|
| Scan before commit | Part 5 (`--staged`, `commit`, hook) |
| Scan before merge | Part 7 (Action) + required check (docs) |
| Block on verified findings | Parts 4–5 (score + policy + exit 1) |
| Cut false positives (entropy + validity) | Part 4 |
| Rotate, don’t just delete / Git history | Part 6 |
| Sample repo with planted flaws | `testdata/` + history demo in Part 6 |
| GitHub Action | Part 7 |
| Enterprise-grade, not a toy grep | Explainable score, redaction, history, honest CI, small config |

---

## Teaching / production rhythm

- Before a part: goal, what you will type, what “done” means.
- After a part: 3–5 questions, one production note in `recommendations.md` if needed.
- I do not write product code unless you ask. You run `cargo` unless you give permission.
- If a design is too big for this list, it goes to Future (below), not into v1.

---

## Build + teach schedule (24 steps, then done)

One step per turn. Each step: I name the 1–2 new ideas in a few lines, you write the code, I review it and note any production nit in `recommendations.md`. No side lessons unless the step needs them or you ask. Questions only at the end of a part, three max.

| Step | You build | New ideas I explain first |
|---|---|---|
| 1.1 | Add `clap` to the project | what a dependency is, `cargo add` |
| 1.2 | Replace the playground: `scan [PATH]` subcommand | `struct`, `enum`, `derive`, `PathBuf` |
| 1.3 | Print `scanning <path>`, check `--help` and exit code | exit codes 0 / 1 / 2 |
| 2.1 | Add `walkdir`, print every file path under a folder | iterators, `Result`, skipping errors instead of crashing |
| 2.2 | Skip `.git`, `target`, `node_modules`, binaries, huge files | bytes vs text, UTF-8, why NUL means binary |
| 2.3 | Add `regex`, 3 rules, print `file:line rule` | regex basics, `lines().enumerate()` |
| 2.4 | `testdata/` with fake secrets; exit 1 on a hit | how CI reads exit codes |
| 3.1 | Move scan logic to `src/lib.rs`, add `Finding` struct + enums | library vs binary crate, `match` |
| 3.2 | `redact()` and a SHA-256 `fingerprint()` | one-way hashing, why we never store the raw value |
| 3.3 | First tests: redaction hides the middle, output has no full secret | `cargo test`, `#[test]`, `mod tests` |
| 4.1 | Shannon `entropy()` + test | entropy as "how random", in plain terms |
| 4.2 | Score = pattern + context + file + entropy, with `why` lines | why one signal is never enough |
| 4.3 | Synthetic validator, threshold 0.65, table of 8 cases | false positive vs false negative |
| 5.1 | Git helper: find repo root, run `git` as a subprocess | working tree vs index vs `HEAD`, `std::process::Command` |
| 5.2 | `scan --staged` | `git diff --cached`, `git show :file` |
| 5.3 | `secgrep commit -m "..."` | running another program and passing its exit code along |
| 5.4 | `install-hook` (pre-commit and `--pre-push`) | what `.git/hooks` is, why `--no-verify` exists |
| 6.1 | Read `git log -p`, pull out added lines | what a diff looks like, `+` lines |
| 6.2 | Group by fingerprint: first seen, last seen, still in tree? | grouping with `HashMap` |
| 6.3 | ROTATE output + demo history test (leak → delete → clean) | why deleting adds a commit instead of erasing one |
| 7.1 | `secgrep.toml` config | TOML, `serde` deserialize, validating user input |
| 7.2 | `--format json` | why machines need stable output |
| 7.3 | GitHub Action + required-check instructions | workflow file, `pull_request`, required status check |
| 7.4 | README, architecture, demo docs, final `cargo test` | what an honest limitations section looks like |

Rules that keep this finite:

- No step gets skipped and no step gets added. If something new comes up, it goes to Future.
- If a step takes more than one attempt, that is fine — it still counts as one step.
- Polish never becomes its own step. It goes in `recommendations.md`.

---

## Future (not v1)

`git2` instead of subprocess, `.gitignore` via `ignore` crate, parallel walk, SARIF, live validation behind an explicit flag, more rules, GitHub PR annotations, `zeroize` for secret buffers.

---

## Current pointer

**Next:** Step 1.1 — add `clap` as a dependency. Nothing else.
