# Gate 0 — Understand the problem (no scanner code)

This is the teaching checkpoint for Phase 0. Read it before you treat `secgrep` as "just another grep for keys."

## 1. The problem in plain English

A developer on a fintech team pasted an API key into a source file so a local script would run. They committed it. Later someone deleted the line and pushed a "fix."

That delete **does not un-leak the key**.

Git is not a folder of "current files." It is a chain of snapshots (commits). The old snapshot still contains the key. Anyone who cloned the repo, forked it, downloaded a CI log, or later ran `git log -p` can recover it.

The only real fix is:

1. **Rotate / revoke** the credential at the provider (AWS, GitHub, Stripe, your bank's API).
2. Remove it from current source (env var or secret manager).
3. Assume history is already exposed — treat it as an incident.

A scanner's job is to **stop the next commit/PR** from adding a new leak, and to **tell you that history still has the old one**.

### Tiny Git thought-experiment

Imagine three commits:

- Commit A: `config.py` contains `API_KEY = "sk_live_...."`.
- Commit B: that line is deleted. `git show HEAD:config.py` looks clean.
- Commit C: you add a README.

`git show A:config.py` still prints the key. GitHub, backups, and every clone that fetched A still have it.

**Rotate. Don't just delete.**

## 2. What existing tools already do well

We are **not** going to pretend a student regex scanner replaces these.

### Gitleaks

Fast open-source scanner. Regex rules + Shannon entropy. Scans directories, Git history (`git log -p`), and stdin. Pre-commit hook and GitHub Action. Configurable `.gitleaks.toml`. No live "is this key still valid?" check.

**Already solved well:** generic secret grep across current files and Git history.

### TruffleHog

Hundreds of detectors. Can **call provider APIs** to see if a key is still live (`verified: true`). Scans Git, filesystems, S3, Docker, and more.

**Already solved well:** distinguishing live credentials from dead/fake ones.

**Cost of that approach:** you are sending candidate secrets to the internet unless you turn verification off. Rate limits. Ethics. We will **not** do this in MVP.

### Semgrep Secrets

Regex + **semantic/dataflow** (understands that a value flowed into an HTTP header) + entropy + validators that run in *your* CI.

**Already solved well:** "this string is used as a credential in real code," not just "it looks random."

Commercial product. We will not clone their engine.

### GitHub Secret Scanning / Push Protection

Runs **on GitHub at push time**, not on your laptop before `git commit`. Public-repo push protection is on by default. It uses partner/high-precision patterns so false positives stay low. Large pushes can time out and **not** block. People can bypass with a reason.

Official docs: [Push protection](https://docs.github.com/en/code-security/concepts/secret-security/push-protection)

**Already solved well:** blocking many well-known token formats from entering GitHub.

**Not a replacement for:** local pre-commit scanning, generic passwords, teaching rotation, or history timelines.

### GitHub Actions does not block merges by itself

If the Action fails, the PR shows a red X. You can still merge unless a **ruleset / branch protection rule requires that status check**.

Official docs: [Require status checks to pass before merging](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)

## 3. Comparison (honest)

| Feature | Gitleaks | TruffleHog | Semgrep Secrets | GitHub | secgrep (us) |
|---|---|---|---|---|---|
| Known key formats | Huge rule set | 700+ detectors | Rules + semantics | Partner patterns | Small high-quality set |
| Git history | Yes | Yes | Mostly current/PR | Alerts after ingest | First/last seen + still-in-history |
| Entropy | Yes | Yes | Yes | Pattern-first | One signal among several |
| Live API validation | No | Yes | Yes (local HTTP) | Partner validity | Adapter only, **default off, no network** |
| Explain *why* | Limited | Verified flag | Product UI | Block message | **Primary feature** |
| Rotate-don't-delete | Mentioned in docs | Detection-focused | Detection-focused | Alert-focused | **First-class report** |
| Pre-commit | Hook | Hook | Hook | No (push-time) | Hook + `secgrep commit` |
| Block PRs | CI + required check | Same | Same | Push protection | Action + documented ruleset |
| Offline core | Yes | Optional verify | Product | GitHub-hosted | Yes, no LLM |

## 4. The gap we actually target (not fake novelty)

We will **not** beat Gitleaks on rule count. We will **not** beat TruffleHog on live verification. We will **not** reimplement GitHub push protection.

We will build:

1. **Explainable confidence** — every finding lists pattern / context / entropy / file signals, and why it was blocked or not.
2. **Historical exposure + rotate-first remediation** — first seen, last seen, in current tree?, still in history?, next actions.
3. **`secgrep commit`** — a wrapper rookies will actually type, plus a hook, plus CI as the real gate.

## 5. Frozen command list (Done means this)

```
secgrep scan .
secgrep scan --staged
secgrep history .
secgrep commit -m "message"
secgrep install-hook
```

Plus `--format text|json`, `secgrep.toml`, GitHub Action, redaction tests, demo with **fake** secrets only.

Out of scope: LLM, GitHub App, live AWS/GitHub HTTP validation, Kubernetes, a website.

## 6. First prerequisites

- **Cargo** is Rust's build tool and package manager. A **crate** is a package of Rust code (this repo is the `secgrep` crate).
- **Git** stores snapshots. `HEAD` is "the commit you are on." The **staging area** (index) is what the next commit will contain. `git commit` snapshots the index, not the whole working tree.

You already need `rustc`, `cargo`, and `git` installed to continue.

## 7. Checkpoint questions (Gate 0)

Answer these for yourself:

1. Why is deleting a key from the current file not enough?
2. Why is TruffleHog's live verification powerful *and* dangerous?
3. Why does a red GitHub Action not always block merge?
4. What two things will secgrep do that Gitleaks is not focused on?
5. Which layer is the real security boundary: hook, `secgrep commit`, or required CI check?

### Practical task

In any Git repo run:

```
git log -1 --oneline
git rev-parse HEAD
```

The long hash is the commit id. That id is a snapshot. Old snapshots do not disappear when you edit files.

When you can explain those five answers, Gate 0 is done. Implementation starts at Gate 1.
