# Unicode Safety Check

A GitHub Action that detects adversarial Unicode in pull requests and pushes. Catches invisible characters, bidirectional text attacks, homoglyph spoofing, Private Use Area code points, variation selector abuse, and encoding issues before they reach your codebase.

**Zero config. Language-agnostic. No dependencies. SARIF output for GitHub Code Scanning.**

Motivated by supply-chain attacks like [Glassworm](https://arstechnica.com/security/2026/03/supply-chain-attack-using-invisible-code-hits-github-and-other-repositories/) (2026) and [Trojan Source](https://trojansource.codes/) (CVE-2021-42574).

## Quick Start

Add to any workflow:

```yaml
- uses: dcondrey/unicode-safety-check@v1
```

That's it. On pull requests it scans only changed files. Findings appear as inline PR annotations.

## What It Detects

| Rule | Category | Characters | Severity |
|------|----------|-----------|----------|
| USC001 | **Bidi overrides** | RLO, LRO, RLE, LRE, PDF, FSI, LRI, RLI, PDI, LRM, RLM, ALM | Error |
| USC002 | **Private Use Area** | U+E000-F8FF, U+F0000-FFFFD, U+100000-10FFFD | Error |
| USC003 | **Tag characters** | U+E0001-E007F (Glassworm-style payload encoding) | Error |
| USC004 | **Invisible characters** | Zero-width space/joiner/non-joiner, word joiner, Mongolian vowel separator, soft hyphen | Error |
| USC005 | **Misplaced BOM** | U+FEFF after byte 0 | Error |
| USC006 | **Annotation anchors** | U+FFF9-FFFB (interlinear annotations) | Error |
| USC007 | **Deprecated format chars** | U+206A-206F, U+FFF0-FFF8 | Error |
| USC008 | **Homoglyphs** | Cyrillic/Greek lookalikes for Latin letters | Warning |
| USC009 | **Invalid encoding** | Non-UTF-8 byte sequences | Error |
| USC010 | **Variation selectors** | U+FE00-FE0F, U+E0100-E01EF (3+ per line flags payload encoding) | Error |

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
      - uses: dcondrey/unicode-safety-check@v1
```

### Full repo scan

```yaml
- uses: dcondrey/unicode-safety-check@v1
  with:
    scan-mode: all
```

### With GitHub Code Scanning (SARIF)

Findings appear in the repository's **Security > Code scanning** tab:

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

      - uses: dcondrey/unicode-safety-check@v1
        id: scan
        with:
          sarif-file: unicode-safety.sarif
        continue-on-error: true

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: unicode-safety.sarif
```

### With options

```yaml
- uses: dcondrey/unicode-safety-check@v1
  with:
    exclude-patterns: |
      docs/translations/
      fixtures/unicode-samples/
    allowlist-file: .unicode-allowlist
    fail-on-warn: 'true'
```

### Using outputs

```yaml
- uses: dcondrey/unicode-safety-check@v1
  id: unicode
- run: echo "Found ${{ steps.unicode.outputs.findings }} issue(s) in ${{ steps.unicode.outputs.files-scanned }} files"
```

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `scan-mode` | `changed` | `changed` scans only PR/push diff; `all` scans the entire repo. |
| `exclude-patterns` | _(none)_ | Newline-separated regex patterns for paths to skip (added to built-in exclusions). |
| `allowlist-file` | _(none)_ | Path to a file with Perl-compatible regexes, one per line. Matching lines are skipped. |
| `fail-on-warn` | `false` | Treat warnings (homoglyphs) as errors that fail the check. |
| `disable-homoglyphs` | `false` | Skip homoglyph detection entirely. |
| `disable-annotations` | `false` | Skip inline PR annotations. |
| `sarif-file` | _(none)_ | Path to write SARIF output. Use with `github/codeql-action/upload-sarif`. |

## Outputs

| Output | Description |
|--------|-------------|
| `findings` | Total number of findings. |
| `files-scanned` | Number of files scanned. |
| `sarif-file` | Path to the SARIF file (if generated). |

## Built-in Exclusions

Binary files are auto-detected and skipped. These paths are excluded by default:

`.git/`, `node_modules/`, `.vscode/`, `__pycache__/`, `vendor/`, `dist/`, `build/`, `_site/`, `.next/`, `target/`, and common binary extensions (`.png`, `.jpg`, `.woff2`, `.pdf`, `.wasm`, `.pyc`, `.class`, `.jar`, `.zip`, `.tar.*`, `.lock`, `.min.js`, `.min.css`, `.map`, `.pb.go`, `*_generated.*`, `*.generated.*`).

## Allowlist File Format

Create a file (e.g., `.unicode-allowlist`) with one Perl-compatible regex per line:

```
# Allow discussion of zero-width characters by code point
U\+200[BCDEF]

# Allow specific test fixtures
test/fixtures/unicode

# Allow soft hyphens in localization files
\.po$.*\x{00AD}
```

Blank lines and lines starting with `#` are ignored.

## How It Works

The scanner uses Perl's native Unicode regex engine (pre-installed on all GitHub runners) to detect dangerous code points. No Docker image, no npm install, no runtime dependencies.

For variation selectors specifically, the check uses a threshold of 3+ selectors per line. Legitimate emoji use typically has one variation selector per base character; Glassworm-style payloads chain dozens of them to encode hidden data.

## Requirements

- `actions/checkout@v4` with `fetch-depth: 0` (needed for diff computation in `changed` mode)
- Runs on `ubuntu-latest` (uses Perl and iconv, both pre-installed)

## License

MIT
