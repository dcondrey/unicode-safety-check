# Unicode Safety Check

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-Unicode%20Safety%20Check-blue?logo=github)](https://github.com/marketplace/actions/unicode-safety-check)
[![CI](https://github.com/dcondrey/unicode-safety-check/actions/workflows/test.yml/badge.svg)](https://github.com/dcondrey/unicode-safety-check/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/v/release/dcondrey/unicode-safety-check)](https://github.com/dcondrey/unicode-safety-check/releases)

Detect adversarial Unicode in pull requests before it reaches your codebase. Language-aware, diff-aware, policy-driven. 19 rules, single-pass scanner, SARIF output.

Catches bidi attacks ([Trojan Source](https://trojansource.codes/)), invisible character injection, homoglyph spoofing, confusable identifier collisions ([Unicode TR39](https://www.unicode.org/reports/tr39/)), variation selector abuse ([Glassworm](https://arstechnica.com/security/2026/03/supply-chain-attack-using-invisible-code-hits-github-and-other-repositories/)), and more.

**Zero config. Language-agnostic. No dependencies.**

## Quick Start

```yaml
name: Unicode Safety
on: [pull_request]
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: dcondrey/unicode-safety-check@v2
```

That's it. Findings appear as inline PR annotations. Only changed lines get the full check; critical checks (bidi, tag chars) run on all lines.

## What It Detects

### Critical (blocks PR)

| Rule | Category | What it catches |
|------|----------|-----------------|
| USC001 | **Bidi controls** | U+202A-202E, U+2066-2069, U+200E/F, U+061C |
| USC002 | **Invisible format chars** | ZWS, ZWNJ, ZWJ, word joiner, soft hyphen |
| USC007 | **Control characters** | Any Cc character except tab/LF/CR |
| USC008 | **Invalid encoding** | Non-UTF-8 byte sequences |
| USC009 | **Misplaced BOM** | Byte-order mark after start of file |
| USC010 | **Variation selectors** | 3+ per line (Glassworm-style payload encoding) |
| USC011 | **Private Use Area** | U+E000-F8FF, supplementary PUA planes |
| USC012 | **Tag characters** | U+E0001-E007F (Glassworm payload encoding) |
| USC013 | **Deprecated format** | U+206A-206F, U+FFF0-FFF8 |
| USC014 | **Annotation anchors** | U+FFF9-FFFB |
| USC015 | **Bidi pairing** | Unbalanced embedding/override/isolate controls |

### High (blocks PR)

| Rule | Category | What it catches |
|------|----------|-----------------|
| USC003 | **Mixed-script identifier** | `paylоad` mixing Latin + Cyrillic in one identifier |
| USC004 | **Confusable collision** | `scope` and `scоpe` in the same file |
| USC016 | **Default-ignorable** | Code points that render as nothing |
| USC017 | **Homoglyphs** | Cyrillic/Greek/Armenian chars that look like Latin |

### Medium (warns)

| Rule | Category | What it catches |
|------|----------|-----------------|
| USC005 | **Suspicious spacing** | NBSP, figure space, thin space, ideographic space |
| USC006 | **Normalization drift** | Text that changes under NFC/NFKC |
| USC018 | **Mixed line endings** | CRLF + LF in the same file |
| USC019 | **Non-ASCII identifier** | Non-ASCII in identifiers when policy is `ascii-only` |

## How It Works

### Language-aware context detection

Rules apply differently based on where the character appears:

| Context | Behavior | Example |
|---------|----------|---------|
| **Identifiers** | Strictest. Mixed-script, confusable collisions, invisible chars all fail. | `paylоad = True` |
| **Comments** | Medium. Most things warn, confusable collisions ignored. | `# TODO: fix lаter` |
| **Strings** | Loosest. Only invisible chars warn. | `"caf\u00e9"` |

20+ languages supported: Python, JavaScript/TypeScript, Go, Rust, Java, C/C++, C#, Ruby, PHP, Shell, YAML, SQL, Swift, Kotlin, Zig, and more.

### Confusable skeleton comparison

Implements [Unicode TR39](https://www.unicode.org/reports/tr39/) confusable skeleton computation. If two identifiers in the same file collapse to the same skeleton, the check fails with both locations:

```
HIGH [USC004 confusable-collision] src/auth.py:42:0
  confusable with 'scope'
  'scоpe' has same skeleton as 'scope' (line 12:0)
  near: "scоpe"
```

### Diff-aware scanning

Only newly added or modified lines get the full 19-rule check. Critical checks (bidi, tag chars, PUA) always run on all lines. This makes the action usable on existing codebases without noise.

### File risk levels

| Risk | File types | Behavior |
|------|-----------|----------|
| **High** | `.py`, `.js`, `.go`, `.rs`, `.yml`, `Dockerfile`, etc. | Critical + high findings fail |
| **Medium** | `.md`, `.html`, `.css`, `.xml` | Only critical findings fail |
| **Low** | `.po`, `locales/**` | Only critical findings fail |

### Rich diagnostics

Every finding shows the code point, Unicode name, escaped representation, and surrounding snippet:

```
CRITICAL [USC001 bidi-control] src/auth.py:118:5
  U+202E RIGHT-TO-LEFT OVERRIDE
  Bidirectional control character U+202E RIGHT-TO-LEFT OVERRIDE in identifier
  near: "isAdmin\u{202E} \u{2066}// check later\u{2069}"
```

## Usage Examples

### With GitHub Code Scanning (SARIF)

Findings appear in the **Security > Code scanning** tab:

```yaml
name: Unicode Safety
on: [pull_request, push]
permissions:
  security-events: write
jobs:
  check:
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

### Full repo scan

```yaml
- uses: dcondrey/unicode-safety-check@v2
  with:
    scan-mode: all
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
| `scan-mode` | `changed` | `changed` scans PR diff only; `all` scans entire repo |
| `policy-file` | | Path to `.unicode-safety.yml` policy file |
| `exclude-patterns` | | Newline-separated path patterns to exclude |
| `fail-on-warn` | `false` | Treat medium/low findings as errors |
| `disable-annotations` | `false` | Skip inline PR annotations |
| `sarif-file` | | Path to write SARIF output |

## Outputs

| Output | Description |
|--------|-------------|
| `findings` | Total finding count |
| `files-scanned` | Number of files scanned |
| `critical` | Critical severity count |
| `high` | High severity count |
| `sarif-file` | Path to SARIF file (if generated) |

## Policy File

Copy [`policy.default.yml`](policy.default.yml) to `.unicode-safety.yml` in your repo and customize:

```yaml
version: 1
encoding: utf-8-only
identifier_policy: ascii-only  # or: latin-extended, permitted-scripts

# Allowlist: path + character + reason (all required)
allow:
  - paths: ["locales/ar/**/*.json"]
    characters: [ZWJ, ZWNJ]
    reason: "Arabic text shaping requires ZWJ/ZWNJ"
  - paths: ["docs/**/*.md"]
    characters: [NBSP]
    reason: "Non-breaking spaces in documentation"

# Per-context rules: fail, warn, or ignore
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

## Design

Strict defaults. Explicit exceptions. Diff-aware checks. Useful failure messages.

- A ZWJ in an Arabic localization string is not the same as a ZWJ in a variable name.
- Allowlists require a path, character, and justification.
- Critical/high findings fail the check. Medium/low findings warn. Teams can tune via policy.
- Single-pass character scanner for performance. No line is iterated more than once.

This action shuts down the class of attacks that rely on hidden controls, invisibles, and homoglyph collisions. It will not solve malicious but fully visible text, parser disagreements downstream, or font-level confusables in every editor.

## CLI Usage

```bash
python3 src/main.py --all                              # scan everything
python3 src/main.py src/auth.py                        # scan specific files
python3 src/main.py --all --policy .unicode-safety.yml # with policy
python3 src/main.py --all --sarif-file results.sarif   # SARIF output
```

## Requirements

- `actions/checkout@v4` with `fetch-depth: 0`
- Python 3.8+ (pre-installed on all GitHub runners)
- No pip dependencies; `pyyaml` auto-installed only if using a YAML policy file

## License

[MIT](LICENSE)
