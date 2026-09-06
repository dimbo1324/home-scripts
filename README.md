# codepack

**Turn a source folder into a clean, safe snapshot you can hand to anyone.**

Point it at a project and it produces an archive plus a set of reports fit to give to a
colleague, a new joiner, a non-technical stakeholder, or a language model. The point is
not compression — it is **not leaking your secrets** when a project leaves your machine:
API keys, tokens, passwords, `.env` files.

Everything runs **locally**. Nothing is uploaded, ever.

---

## Contents

- [What you get](#what-you-get)
- [Install](#install)
- [Quick start](#quick-start)
- [Commands](#commands)
- [Archive formats](#archive-formats)
- [Sterile copy](#sterile-copy)
- [Hand a bundle to a local agent](#hand-a-bundle-to-a-local-agent)
- [Let an agent ask for itself (MCP)](#let-an-agent-ask-for-itself-mcp)
- [Scanning git history](#scanning-git-history)
- [Labelled redaction](#labelled-redaction)
- [Pre-commit use](#pre-commit-use)
- [In CI](#in-ci)
- [Guarantees](#guarantees)
- [Documentation](#documentation)
- [Developing](#developing)

---

## What you get

Two ways to use it, both over the same engine — neither is a wrapper around the other.

**Desktop app** (Windows 10/11). An export wizard, a preview tree where you can override
what goes in and what stays out, a results panel, run history, folder watching, light and
dark themes, English and Russian interfaces switchable without a restart, and a tray icon.

**Command line** — the `codepack` binary. Twelve commands plus the MCP server, a stable
exit-code contract, and `--json` on everything.

**MCP server** — `codepack mcp`, for a coding agent rather than a person. Same engine,
same answers, spoken over a pipe.

A finished export contains the selected source files, a directory structure report, git
history and optionally a patch, a full text dump, roughly thirty analysis reports, an
`AI_CONTEXT` folder written for a language model, a security scan (including SARIF), and
a manifest describing all of it.

> **Screenshots.** Not included yet. They were attempted for this release and abandoned:
> capturing a window on Windows grabs whatever is actually on top of that screen region,
> which risks putting unrelated private content into a public repository. Add them by
> running the app and capturing its window deliberately.

## Install

Build the installer from the repository:

```bash
cargo xtask package
```

The NSIS `.exe` lands in `target/release/bundle/nsis/`.

The build is **not code-signed yet**, so Windows SmartScreen will warn about an unknown
publisher. Signing, notarisation, checksums and auto-update are planned but not done.

For the command line only:

```bash
cargo build --release -p codepack-cli
```

## Quick start

See what an export would include, without writing anything:

```bash
codepack preview .
```

Then produce the bundle:

```bash
codepack export . --preset "Claude Code" --out ../out
```

Six presets ship: `Claude Code`, `ChatGPT`, `Code Review`, `Security Audit`, `Онбординг`
(onboarding), and `PR Review` — the last narrowing the export to uncommitted changes, for
discussing one pull request rather than a whole project.

A token budget can be a number or a **model name**, resolved through a built-in table you
can extend with your own file — no rebuild needed:

```bash
codepack export . --budget Claude
codepack export . --budget 200k
```

If a file is missing from the bundle and you cannot see why:

```bash
codepack explain src/main.rs
```

It answers with one of four verdicts — included, excluded (naming the rule), not in the
diff selection, or not planned at all (naming the skipped directory) — and all four are a
success, because "it was excluded, here is why" is the explanation working.

## Commands

| Command | What it does |
|---|---|
| `export` | The full pipeline: plan → copy → structure → git → text dump → analytics → manifest → archive |
| `preview` | What an export would include. Writes **nothing** |
| `scan` | Find secrets and risky code. `--staged` is the pre-commit mode |
| `verify` | Re-scan a bundle that already exists — the only check its recipient can run |
| `explain <file>` | Why one file did or did not make it into the export |
| `sanitize` | Sterile copy: code with comments stripped and reformatted, optionally archived |
| `handoff <bundle>` | Point a coding agent on this machine at a finished bundle |
| `init --hook` | Install the pre-commit hook into this project |
| `mcp` | Serve the Model Context Protocol on stdin/stdout, for a coding agent |
| `history` | Previous runs |
| `doctor` | Environment diagnostics |
| `completions <shell>` | A shell completion script |

**Exit codes are a contract** you can build a pipeline on: `0` success, `1` error,
`2` bad arguments, `3` critical secrets found. A real failure always outranks "secrets
found" — a run that broke never reports `3`, because that would tell your pipeline the
scan result can be trusted when it cannot.

**`--json`** works on every command. It carries a schema version, goes only to stdout, and
leaves progress and errors on stderr, so `codepack export --json | jq` does not break on
the first log line.

## Archive formats

ZIP by default, everywhere. 7z is available when you want smaller archives. RAR is offered
in the interface but **not implemented** — there is no permissively licensed RAR encoder to
depend on, so it is reserved and refused with a message rather than silently producing a
ZIP with the wrong extension.

```bash
codepack export . --archive-format 7z
codepack sanitize --source . --archive ../clean.zip
```

For `sanitize`, the file extension picks the container; `--archive-format` overrides it.

## Sterile copy

A standalone action, not a step of the export: it builds a copy of the project with
comments removed by real parsers (tree-sitter, never regular expressions) and the code
reformatted wherever a suitable formatter is found on your `PATH`.

```bash
codepack sanitize --source . --archive ../project-sterile.zip
```

`--out` is only needed if you also want the folder. With just `--archive`, the copy is made
in a temporary directory that cleans itself up, and one file is the whole result. You can
ask for both:

```bash
codepack sanitize --source . --out ../sterile --archive ../project-sterile.zip
```

The archive contains exactly the files this run produced, plus
`STERILE_COPY_REPORT.json`/`.md` — so whoever receives it gets the account of what was
stripped, skipped and redacted alongside the code it describes.

## Hand a bundle to a local agent

Claude Code and Codex run on your machine and read your filesystem, so there is nothing to
upload:

```bash
codepack handoff ../out/myproject.zip --agent claude-code --question "Find the auth bugs"
```

It writes `AI_HANDOFF.md` into the bundle — a briefing that says where to start and warns
that the snapshot is partial by design — and prints the command to run there. A `.zip` is
unpacked beside itself first, because an agent cannot read a project inside an archive.
The desktop app offers the same thing on the Result page.

Nothing is sent anywhere and nothing is launched. The binary contains **no HTTP client at
all**: the crate that can reach the network is compiled without it, and the quality gate
fails the build if that ever changes.

## Let an agent ask for itself (MCP)

Handing a bundle over is a one-way gesture: the assistant reads what it was given, and
when a file is missing it can only guess why. `codepack mcp` closes that loop — it speaks
the Model Context Protocol over stdin/stdout, so an agent already running on your machine
can ask the same questions you ask at the terminal.

Point Claude Code at it:

```bash
claude mcp add codepack -- codepack mcp
```

or, for any client that reads a JSON config:

```json
{
  "mcpServers": {
    "codepack": { "command": "codepack", "args": ["mcp"] }
  }
}
```

Four tools:

| Tool | What the agent gets |
|---|---|
| `codepack_preview` | What an export would include and what it would drop, and why. Writes nothing |
| `codepack_scan` | Secrets in the working tree, in the staged changes, or anywhere in the git history |
| `codepack_explain` | Why one specific file is in or out — the question a bundle alone cannot answer |
| `codepack_export` | The full pipeline. The only tool that writes anything, and it says so |

It is **stdio, not HTTP**: no port, no network client in the binary, nothing to expose.
The tools call the same code the commands call, so an agent and a person cannot get
different answers about the same project. A tool that fails answers with the reason
rather than an error the model never sees.

## Scanning git history

Deleting a credential from a file does not remove it from the commits that carried it,
and those travel with every clone. This is the check that answers "was a secret ever
committed", which is the question rotation depends on:

```bash
codepack scan --history
codepack scan --history --since origin/main
```

Each distinct version of each file is scanned once and every finding names the commit that
introduced it, with the full timestamp. Two limits keep the walk bounded — 500 commits by
default (`--max-commits 0` for all of them) and 8 MB per file version — and **both are
reported**, because a clean result over part of a history is not a clean history.

## Labelled redaction

By default every secret is replaced with the same `<REDACTED>`, so a reader cannot tell
whether two redacted values are one credential or two. Turn labels on and each distinct
secret gets a stable name instead:

```toml
# .codepack.toml
redaction_labels = true
```

```text
api.py:    api_key = <REDACTED:s1>
worker.py: token: <REDACTED:s1>      ← the same credential
worker.py: password = <REDACTED:s2>  ← a different one
```

The label is a position in a list, never derived from the value: a hash would let anyone
holding the bundle confirm a guessed password, and the value never leaves the redactor.
Labels are per-bundle, and off by default, so an existing configuration produces exactly
what it always did.

## Pre-commit use

```bash
codepack init --hook
```

That installs a hook running `codepack scan --staged` on every commit. It honours
`core.hooksPath`, refuses to overwrite a hook it did not write (`--force` overrides), and
— if `codepack` is not installed on the machine running it — says so loudly on stderr and
lets the commit through rather than blocking a colleague over a tool they never chose.

```bash
codepack scan --staged
```

This reads content **from the git index**, not from your working tree — a commit is built
from the index, and the two diverge the moment a staged file is edited again.

Findings you have reviewed and accepted go in a `.codepack-allow` file beside the project.
The fingerprint is computed from the rule, the file, and the **already-redacted** message —
the secret itself is never an input. Suppressed findings are still counted and printed, so
they never disappear silently.

By default a commit is blocked only by a `critical` finding, which is the published
contract. Raise it when you want to:

```bash
codepack scan --staged --fail-on high
```

## In CI

`scan` writes SARIF 2.1.0, so findings can become code-scanning alerts:

```bash
codepack scan --sarif codepack.sarif
```

There is a ready-made GitHub Action in this repository:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0 # only needed for history scanning
- uses: dimbo1324/codepack@main
  with:
    history: "true"
    since: ${{ github.event.pull_request.base.ref }}
    fail-on: critical
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: codepack.sarif
```

The action builds codepack from source on the runner: there are no signed release
binaries yet, and downloading an unsigned one would be the very thing this tool argues
against. Pin `ref:` to a commit for reproducible runs.

## Guarantees

These are held by tests, not by promises in this file:

- **Privacy is absolute.** No crate reaches the network except the explicit, user-initiated
  AI integration. A quality-gate step reads every manifest and fails the build otherwise.
- **The source is immutable.** An export never writes inside the folder it reads — refused
  by the engine both front ends go through, before anything is created on disk.
- **Secrets never reach what codepack writes.** Not a report, a log, the history, the
  database, an error message, or the text dump — never in the clear.
- **Bundles do not name your machine.** `source_root` and the paths beside it carry the
  project's name, not `C:\Users\<you>\...`, so a bundle handed to somebody else discloses
  neither your account name nor the shape of your working directories. Turn
  `disclose_absolute_paths` on if you would rather have the real paths in your own
  bundles.
- **Copied source files are included unchanged.** An export copies the files it selects
  byte for byte rather than rewriting them, so what keeps a credential out of the archive
  is the *selection*: safe mode excludes `.env` files, key material and similarly named
  files. A live key inside an ordinary source file travels with that file — read the
  security report and the preview before handing a bundle to someone.
- **Byte figures are preserved.** Token counts were added alongside, not instead.
- **Symlinks are never followed** — while walking, while copying, and while reading a
  bundle back — and extraction is path-traversal safe and bounded in size, depth and
  member count.

The full registry, with the reasoning behind each one, is in
[docs/architecture/invariants.md](docs/architecture/invariants.md).

## Documentation

| Document | What it answers |
|---|---|
| [docs/architecture/overview.md](docs/architecture/overview.md) | What is actually built, and how the pieces fit |
| [docs/architecture/invariants.md](docs/architecture/invariants.md) | What must never break, and why |

## Developing

```bash
python dev_tools_scripts_runner.py list   # the catalogue of routine jobs
cargo xtask gate                          # the full quality gate
cargo xtask fmt                           # format Rust and the frontend
pnpm desktop:dev                          # run the app with hot reload
```

`cargo xtask gate` is the check that must pass: formatting, clippy with warnings denied,
tests, dependency audit, frontend checks, the dev-script suite, agent-rule sync, and
network isolation.

Target platform is **Windows 10/11**. macOS and Linux remain a goal; the disabled code is
marked rather than deleted.
