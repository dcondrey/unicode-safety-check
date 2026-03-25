# Unicode Safety Check

A GitHub Action that detects adversarial Unicode in pull requests. Language-aware, diff-aware, policy-driven.

Catches bidi attacks, invisible characters, homoglyph spoofing, confusable identifier collisions, variation selector abuse, suspicious spacing, normalization drift, control characters, and encoding issues.

**Zero config. Language-agnostic. SARIF output for Code Scanning.**

## Quick Start

```yaml
- uses: dcondrey/unicode-safety-check@v2
```

On pull requests, only changed lines get the full check. Critical checks (bidi, tag chars) run on all lines.

## What It Detects

| Rule | Category | Severity | What it catches |
|------|----------|----------|-----------------|
| USC001 | **Bidi controls** | Critical | U+202A-202E, U+2066-2069, U+200E/F, U+061C. Trojan Source primitives. |
| USC002 | **Invisible format chars** | Critical | ZWS, ZWNJ, ZWJ, word joiner, soft hyphen, Mongolian vowel separator. |
| USC003 | **Mixed-script identifier** | High | Single identifier mixing Latin + Cyrillic, Latin + Greek, etc. |
| USC004 | **Confusable collision** | High | Two identifiers in the same file that collapse to the same skeleton. |
| USC005 | **Suspicious spacing** | Medium | NBSP, figure space, thin space, ideographic space in code. |
| USC006 | **Normalization drift** | Medium | Text that changes under NFC/NFKC normalization. |
| USC007 | **Control characters** | Critical | Any Cc character except tab, newline, carriage return. |
| USC008 | **Invalid encoding** | Critical | Non-UTF-8 byte sequences. |
| USC009 | **Misplaced BOM** | Critical | Byte-order mark after start of file. |
| USC010 | **Variation selectors** | Critical | 3+ variation selectors per line (Glassworm-style payload encoding). |
| USC011 | **Private Use Area** | Critical | U+E000-F8FF, supplementary PUA planes. |
| USC012 | **Tag characters** | Critical | U+E0001-E007F (Glassworm payload encoding). |
| USC013 | **Deprecated format** | Critical | U+206A-206F, U+FFF0-FFF8. |
| USC014 | **Annotation anchors** | Critical | U+FFF9-FFFB (interlinear annotations). |
| USC015 | **Bidi pairing** | Critical | Unbalanced bidi embedding/override/isolate controls. |
| USC016 | **Default-ignorable** | High | Default-ignorable code points outside specific known categories. |
| USC017 | **Homoglyphs** | High | Cyrillic/Greek/Armenian characters that look like Latin. |
| USC018 | **Mixed line endings** | Medium | CRLF + LF in the same file. |
| USC019 | **Non-ASCII identifier** | Medium | Non-ASCII in identifiers when policy is `ascii-only`. |

## Key Features

### Language-aware context detection

Rules are applied differently based on lexical context:

- **Identifiers**: strictest rules (mixed-script, confusable collision, invisible chars all fail)
- **Comments**: medium rules (most things warn, confusable collisions ignored)
- **Strings**: loosest rules (only invisible chars warn)

Supported languages: Python, JavaScript/TypeScript, Go, Rust, Java, C/C++, C#, Ruby, PHP, Shell, YAML, SQL, and more.

### Diff-aware scanning

By default, only newly added or modified lines get the full check suite. Critical checks (bidi controls, tag characters, PUA) always run on all lines. This cuts noise on existing codebases.

### Confusable skeleton comparison

Computes Unicode TR39 confusable skeletons for all identifiers in a file. If two different identifiers collapse to the same skeleton (`scope` vs `scоpe`), the check fails with both locations.

### File risk levels

Files are classified by risk:

- **High risk** (code, config, CI): critical + high findings fail the check
- **Medium risk** (docs, markup): only critical findings fail
- **Low risk** (localization): only critical findings fail, most checks are advisory

### Rich diagnostics

Every finding includes the Unicode code point, character name, escaped representation, and a surrounding text snippet:

```
CRITICAL [USC001 bidi-control] src/auth.py:118:5
  U+202E RIGHT-TO-LEFT OVERRIDE
  Bidirectional control character in identifier
  near: "isAdmin\u{202E} \u{2066}// check later\u{2069}"
```

## Usage

### Basic (PR checks)

```yaml
name: Security
on: [pull_request]
jobs:
  unicode-safety:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: dcondrey/unicode-safety-check@v2
```

### Full repo scan

```yaml
- uses: dcondrey/unicode-safety-check@v2
  with:
    scan-mode: all
```

### With Code Scanning (SARIF)

```yaml
name: Security
on: [pull_request, push]
permissions:
  security-events: write
jobs:
  unicode-safety:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: dcondrey/unicode-safety-check@v2
        id: scan
        with:
          sarif-file: unicode-safety.sarif
        continue-on-error: true
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: unicode-safety.sarif
```

### With policy file

```yaml
- uses: dcondrey/unicode-safety-check@v2
  with:
    policy-file: .unicode-safety.yml
```

### Using outputs

```yaml
- uses: dcondrey/unicode-safety-check@v2
  id: scan
- run: |
    echo "Findings: ${{ steps.scan.outputs.findings }}"
    echo "Critical: ${{ steps.scan.outputs.critical }}"
    echo "High: ${{ steps.scan.outputs.high }}"
```

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `scan-mode` | `changed` | `changed` scans PR diff only; `all` scans entire repo. |
| `policy-file` | _(none)_ | Path to `.unicode-safety.yml` policy file. |
| `exclude-patterns` | _(none)_ | Newline-separated path patterns to exclude. |
| `fail-on-warn` | `false` | Treat medium/low findings as errors. |
| `disable-annotations` | `false` | Skip inline PR annotations. |
| `sarif-file` | _(none)_ | Path to write SARIF output. |

## Outputs

| Output | Description |
|--------|-------------|
| `findings` | Total finding count. |
| `files-scanned` | Files scanned. |
| `critical` | Critical severity count. |
| `high` | High severity count. |
| `sarif-file` | Path to SARIF file (if generated). |

## Policy File

Copy `policy.default.yml` to `.unicode-safety.yml` in your repo:

```yaml
version: 1
encoding: utf-8-only
identifier_policy: ascii-only  # or: latin-extended, permitted-scripts

# Allowlist specific characters in specific paths
allow:
  - paths: ["locales/ar/**/*.json"]
    characters: [ZWJ, ZWNJ]
    reason: "Arabic text shaping"
  - paths: ["docs/**/*.md"]
    characters: [NBSP]
    reason: "Non-breaking spaces in docs"

# Per-context rules
contexts:
  identifier:
    mixed-script: fail
    confusable-collision: fail
    invisible-format: fail
  comment:
    mixed-script: warn
    invisible-format: warn
  string:
    invisible-format: warn
```

## Design Philosophy

This action catches the obvious bad stuff, surfaces the ambiguous stuff, and allows explicit exceptions.

- **Strict defaults.** Bidi controls, invisible characters, and confusable collisions fail immediately.
- **Explicit exceptions.** Allowlists require a path, character, and reason.
- **Diff-aware.** Only new or modified lines get the full check. Existing code is not blocked.
- **Useful diagnostics.** Every finding shows the code point, Unicode name, and escaped snippet.
- **Context-sensitive.** A ZWJ in an Arabic string is not the same as a ZWJ in a variable name.
- **Severity buckets.** Critical/high findings fail. Medium/low findings warn. Teams can tune this.

What this action will not solve: malicious but fully visible text, parser disagreements downstream, font-level confusables in every editor, unsafe copy/paste into terminals. But it shuts down the class of attacks that rely on hidden controls, invisibles, and homoglyph collisions.

## Requirements

- `actions/checkout@v4` with `fetch-depth: 0`
- Python 3.8+ (pre-installed on all GitHub runners)
- No pip dependencies for default config; `pyyaml` auto-installed only if using a YAML policy file

## CLI Usage

Run locally without GitHub Actions:

```bash
# Scan specific files
python3 src/main.py src/auth.py src/config.py

# Scan entire directory
python3 src/main.py --all

# With policy
python3 src/main.py --all --policy .unicode-safety.yml

# SARIF output
python3 src/main.py --all --sarif-file results.sarif
```

## License

MIT
