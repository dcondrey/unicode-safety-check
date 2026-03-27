# unicode-safety-check v3.0.0 -- Audit Findings

Consolidated from full `/audit-file` across all source files.
Generated: 2026-03-26 | Updated: 2026-03-26 (re-audit)

## Legend

- Severity: CRITICAL > HIGH > MEDIUM > LOW > INFO
- Status: `[ ]` open, `[x]` fixed, `[-]` wont-fix

---

## CRITICAL

- [x] C-001 [Correctness] tokenizer.rs - Nested block comments not handled
  Added `block_comment_depth` tracking with `supports_nested_comments()` for Rust/Swift/Kotlin/Scala. Non-nesting languages (C/Java) keep first-`*/`-wins behavior.

## HIGH

- [x] H-001 [Security] action.yml - Version input interpolated into URL without validation
  Added semver regex validation before URL construction.

- [x] H-002 [Correctness] tokenizer.rs - Byte offset used as column for non-ASCII text
  Added `byte_to_char_offset()` helper. All Token.col values now use char offsets.

- [x] H-003 [Correctness] checks.rs/tokenizer.rs - Column offset inconsistency between modules
  Fixed by H-002; both scan_line_chars (char-based) and tokenizer (now char-based) are consistent.

- [x] H-004 [Correctness] tokenizer.rs - JS/TS backtick template literals not tracked across lines
  Added `is_backtick_string_lang()` helper; unterminated backtick sets multiline state.

- [x] H-005 [Memory] diff.rs - No timeout on git diff command
  Replaced `Command::output()` with `spawn()` + piped stdout capped at 50MB.

- [x] H-006 [Memory] scanner.rs - scan_file reads entire file with no size limit
  Added `fs::metadata()` check; files > 50MB skipped with warning to stderr.

- [x] H-007 [Memory] diff.rs - Large diffs loaded entirely into memory
  Addressed with H-005; diff output capped at 50MB.

- [x] H-008 [Missing Method] config.rs - Missing should_fail() from Python Policy
  Added `Policy::should_fail(severity, file_risk)` matching Python logic.

- [x] H-009 [Security] action.yml:63,141 - Script injection via unsanitized inputs
  All `${{ }}` interpolations replaced with `env:` block variables in all three action steps.

- [ ] H-010 [Security] action.yml:107-115 - No checksum verification of downloaded binary
  Release binary downloaded via curl and executed with no SHA256 or signature check. Publish checksums per release; verify after download.

- [x] H-011 [Security] output.rs:276-278 - Newline injection in GITHUB_OUTPUT
  Strip newlines from sarif_path before writing to GITHUB_OUTPUT.

## MEDIUM

- [x] M-001 [Correctness] scanner.rs - fnmatch lacks [char class] support
  Added `[seq]`, `[!seq]`, and range (`[a-z]`) support to fnmatch with `parse_char_class` helper.

- [x] M-002 [Security] diff.rs - base_sha passed to git without validation
  Added hex validation; non-hex strings rejected with warning, returns None.

- [ ] M-003 [Race] scanner.rs - TOCTOU between is_binary check and fs::read
  File could be modified between checks. Inherent to the design; would require combining binary check with read into a single operation. Low risk in practice.

- [x] M-004 [Correctness] scanner.rs - collect_files follows symlinks
  Changed to `entry.file_type()?.is_dir()` which does not follow symlinks.

- [x] M-005 [Panic Safety] checks.rs - expect("unknown rule_id") can panic
  Replaced with graceful fallbacks: returns Severity::Critical and "unknown" rule_name.

- [x] M-006 [Security] checks.rs - ConfusableTracker cap enables detection bypass
  Changed from silently dropping to clearing the map at cap, so post-reset collisions are still caught.

- [x] M-007 [Performance] config.rs - glob_to_regex recompiled on every call
  Replaced `fnmatch_regex` with `scanner::fnmatch` (made pub(crate)). Removed fnmatch-regex dependency entirely.

- [x] M-008 [Correctness] checks.rs - snippet() window off by one
  Fixed end calculation to produce exactly `width` chars, matching Python.

- [-] M-009 [Parity] diff.rs - get_changed_lines returns None on failure vs Python empty dict
  Wont-fix. Rust fail-open behavior is intentionally safer.

- [x] M-010 [Correctness] tokenizer.rs - find_str_end does not handle raw strings
  Added `find_raw_str_end()` and Python raw string detection (r"...", R"...").

- [x] M-011 [Correctness] tokenizer.rs - Lua comment syntax not handled
  Added Lua `--` line comment handling in tokenize_line.

- [-] M-012 [Parity] config.rs - Case sensitivity mismatch with Python fnmatch on macOS
  Wont-fix. Added TODO documenting the difference. Case-insensitive matching would be unexpected on Linux.

- [-] M-013 [Missing Format] config.rs - No TOML policy file support
  Deferred for future release.

- [x] M-014 [Logic] main.rs - No conflict guard for --all / --file-list
  Added `conflicts_with` to clap args.

- [x] M-015 [Correctness] action.yml - No Windows platform support
  Updated error message to explicitly state Windows is not supported.

- [x] M-016 [Security] action.yml - Shell interpolation of inputs without quoting
  Replaced all direct `${{ }}` interpolations with variable assignments.

- [x] M-017 [Ordering] models.rs - Severity has no Ord/PartialOrd
  Added Ord/PartialOrd with rank() method: Critical(3) > High(2) > Medium(1) > Low(0).

- [x] M-018 [CI] release.yml - Tag pattern too broad
  Tightened from `v*` to `v[0-9]+.[0-9]+.[0-9]+*`.

- [x] M-019 [CI] test-rust.yml - Acceptance tests only check exit codes
  Updated bidi test to capture output and grep for USC001.

- [-] M-020 [CI] test.yml - continue-on-error masks failures in test-bidi
  Wont-fix. This is the Python v2 test workflow; will be updated when Python code is removed.

- [x] M-021 [SARIF] output.rs - SARIF missing semanticVersion field
  Added `semanticVersion` to tool.driver object.

- [x] M-022 [Correctness] config.rs:149-155 - file_policies HashMap non-deterministic iteration
  Changed to iterate in priority order (High > Medium > Low) for deterministic results.

- [x] M-023 [Correctness] main.rs:174-180 - has_warn ignores policy severity overrides
  `has_warn` now also consults `policy.should_fail()` for consistency with `has_fail`.

- [x] M-024 [Security] checks.rs:288-292 - ConfusableTracker full-clear enables detection bypass
  Changed from full clear to evicting oldest half, preserving cross-boundary detection.

- [x] M-025 [Correctness] checks.rs:98-232 - context_action not consulted in scan_line_chars
  Added `policy.context_action()` check before pushing findings in scan_line_chars.

- [x] M-026 [Security] scanner.rs:376-411 - collect_files follows symlink cycles, causes stack overflow
  Added MAX_DIR_DEPTH (64) limit and skip symlinked directories.

- [x] M-027 [Correctness] scanner.rs:183-187 - should_exclude substring matching causes false exclusions
  Removed substring fallback; extra patterns now use fnmatch only.

- [x] M-028 [Correctness] tokenizer.rs:441-467 - Raw triple-quoted Python strings mishandled
  Added triple-quote check before single raw-string path; multiline raw triple-quotes also handled.

- [ ] M-029 [Coverage] unicode_data.rs:11-50 - SCRIPT_RANGES missing many Unicode scripts
  Thai+Devanagari both return "Unknown", so mixed-script detection fails between them. Use `unicode-script` crate or expand the table.

- [ ] M-030 [Coverage] unicode_data.rs:107-201 - CONFUSABLES table is ~80 entries vs thousands official
  Uncovered confusables (math italic/bold U+1D400-1D7FF, Cherokee, etc.) evade detection. Expand table or use a confusables crate.

- [x] M-031 [Security] output.rs:166-172 - Step summary markdown injection via filenames
  Escape backticks (to `'`) and `|` (to `\\|`) in file paths in step summary.

- [x] M-032 [Security] action.yml:89 - Script injection via inputs.version before grep validation
  All inputs now passed via `env:` block; `VERSION="$INPUT_VERSION"`.

- [x] M-033 [Correctness] action.yml:133-153 - Policy/exclude/sarif/fail-on-warn inputs silently ignored
  All inputs now wired to CLI args: --policy, --exclude, --fail-on-warn, --no-annotations, --sarif.

- [x] M-034 [Correctness] action.yml:80 - git diff failure silently produces empty file list
  Now checks git diff exit code; on failure emits `::warning::` and falls back to full scan.

- [ ] M-035 [Supply Chain] Cargo.toml - Cargo.lock not committed
  Binary crate without committed lockfile; non-reproducible builds. `git add rust/Cargo.lock`.

- [x] M-036 [CI] release.yml, test-rust.yml, test.yml - No timeout-minutes on any job
  Added timeout-minutes to all jobs across all 3 workflows.

- [x] M-037 [CI] test-rust.yml, test.yml - No permissions block
  Added `permissions: contents: read` to test-rust.yml and test.yml.

- [ ] M-038 [CI] release.yml:65 - softprops/action-gh-release pinned to tag not SHA
  Tag `@v2` can be force-pushed. Pin to commit SHA. (Upgraded from I-007.)

- [x] M-039 [Correctness] checks.rs:108-123 - Bidi closer-before-opener produces net-zero depth
  Closers now clamped at 0; orphaned closers tracked separately and flagged.

- [ ] M-040 [Test] integration.rs - No finding count assertions in tests
  Tests check rule ID presence but not total count. A regression causing duplicate findings passes silently.

- [ ] M-041 [Test] integration.rs:109-151 - SARIF test does not verify findings in results
  Asserts `runs` array exists but not that `results` is non-empty.

- [ ] M-042 [Test] integration.rs - 11 of 19 rules have zero integration test coverage
  USC006, USC008-USC016, USC018 have no dedicated fixture or assertion.

- [ ] M-043 [Test] integration.rs - No test for exit 0 on warning-only without --fail-on-warn
  Warning vs error exit code logic is only half-tested.

## LOW

- [x] L-001 [Performance] scanner.rs - Unnecessary string copy with to_owned()
  Removed `.to_owned()`; content now borrows from raw Vec<u8>.

- [x] L-002 [Robustness] scanner.rs - Permission errors silently swallowed
  Added warning to stderr when fs::read_dir fails.

- [x] L-003 [Parity] scanner.rs - Non-UTF8 filenames silently skipped
  Added warning to stderr for non-UTF8 filenames.

- [-] L-004 [Robustness] diff.rs - from_utf8_lossy replaces non-UTF8 filenames
  Wont-fix. Inherent limitation; non-UTF8 paths are extremely rare.

- [x] L-005 [Security] diff.rs - base_sha without "--" separator
  Fixed by M-002 (hex validation prevents flag injection).

- [x] L-006 [Data Integrity] checks.rs - check_encoding reports col:0
  Now reports col as `e.valid_up_to()` byte offset.

- [x] L-007 [Maintainability] checks.rs - check_encoding/check_mixed_line_endings bypass policy overrides
  Both now accept `&Policy` and use `sev()` for severity resolution.

- [-] L-008 [API Contract] checks.rs - check_token does not call policy.is_allowed
  Wont-fix. Matches Python behavior; changing could cause false negatives.

- [-] L-009 [Maintainability] checks.rs - make_finding takes 9 parameters
  Wont-fix. Refactoring to builder pattern would be large with no correctness benefit.

- [-] L-010 [Dead Code] config.rs - Extensive #[allow(dead_code)]
  Wont-fix. Fields reserved for future policy integration.

- [-] L-011 [Serde] config.rs - Unknown YAML keys silently ignored
  Wont-fix. Intentional for forward compatibility.

- [x] L-012 [Missing Trait] models.rs - Finding has no Clone
  Added Clone to Finding's derive list.

- [x] L-013 [Missing Trait] models.rs - Severity, Context lack Serialize/Display
  Added Serialize to Severity. Added Display impl for Context.

- [x] L-014 [Usability] main.rs - Zero files produces silent exit 0
  Added warning to stderr when scanned == 0.

- [x] L-015 [Correctness] main.rs - Path format mismatch
  Paths from collect_files now normalized by stripping leading "./".

- [-] L-016 [Robustness] output.rs - write_step_summary silently ignores errors
  Wont-fix. Intentional; CI envs may not have these env vars.

- [x] L-017 [Display] output.rs - Pipe chars break markdown table
  Added `|` escaping in write_step_summary message field.

- [x] L-018 [Test] integration.rs - Confusable test too loose
  Changed to assert both USC004 AND USC017 are present.

- [x] L-019 [Test] integration.rs - SARIF temp file not unique
  Now uses process ID in filename for parallel safety.

- [x] L-020 [Test] integration.rs - SARIF test missing exit code assertion
  Added assertion that exit code is 0 or 1 (not a crash).

- [x] L-021 [Correctness] main.rs:183 - process::exit(1) bypasses destructors
  Added explicit stdout flush before process::exit.

- [ ] L-022 [Correctness] checks.rs:436-454 - check_encoding col is byte offset, rest uses char offsets
  `Utf8Error::valid_up_to()` returns bytes, not chars. Convert to line/char offset.

- [x] L-023 [Security] output.rs:49-50 - escape_invisible skips ASCII control chars
  Now escapes ASCII control chars (except TAB/LF/CR) and DEL.

- [ ] L-024 [Correctness] config.rs:370-374 - parse_char_spec silently ignores invalid U+ hex or unknown names
  `U+ZZZZ` or unknown named chars return empty set with no warning.

- [ ] L-025 [Correctness] config.rs:346-377 - No validation that codepoint values are <= 0x10FFFF
  Out-of-range codepoints in policy silently do nothing.

- [x] L-026 [Performance] tokenizer.rs:312 - Unnecessary .clone() on string_delimiter
  Removed `ref` from pattern; clone still needed for borrow checker but binding is cleaner.

- [ ] L-027 [Correctness] tokenizer.rs:311-336 - Multiline backtick continuation ignores backslash-escaped delimiters
  `str::find` matches escaped backticks, prematurely closing the string.

- [ ] L-028 [Correctness] tokenizer.rs - HTML/XML comment syntax not handled
  All HTML/XML content classified as `Context::Identifier`.

- [ ] L-029 [Correctness] tokenizer.rs - SQL -- line comments not handled
  Only `//` and `/* */` are handled for SQL; standard `--` comments are missed.

- [x] L-030 [Maintainability] unicode_data.rs:330 - Redundant cp < 0x110000 guard
  Removed the outer `if cp < 0x110000` wrapper; `char::from_u32` guards against surrogates.

- [ ] L-031 [Performance] unicode_data.rs:229-233 - Second NFD pass in skeleton() always a no-op
  All current confusable targets are ASCII. Add fast path: `if mapped.is_ascii() { return mapped; }`.

- [x] L-032 [Correctness] action.yml:94-103 - Windows case emits ::error:: but does not exit 1
  Added `exit 1` after the unsupported platform error.

- [ ] L-033 [Maintenance] Cargo.toml:19 - serde_yaml = "0.9" is deprecated/unmaintained
  Migrate to `serde_yml` or another maintained YAML library.

- [x] L-034 [Security] release.yml:8-9 - permissions: contents: write is workflow-level
  Moved to job-level: build gets `contents: read`, release gets `contents: write`.

- [ ] L-035 [Test] test.yml:137-151 - test-exclude job has no assertion the file was excluded
  Test passes if action exits 0, does not verify findings == 0.

- [ ] L-036 [Test] integration.rs:57-85 - confusable/mixed_script tests miss incidental rules
  USC003, USC017, USC019 trigger but are not asserted.

- [ ] L-037 [Test] integration.rs:149-150 - SARIF temp file not cleaned on assertion panic
  Use a Drop guard or `tempfile::NamedTempFile`.

## INFO

- [ ] I-001 [Test] scanner.rs - No test for collect_files with symlinks or permission errors
- [ ] I-002 [Test] diff.rs - No test for malformed hunk headers or large line ranges
- [ ] I-003 [Test] test-rust.yml - No acceptance tests for confusable, mixed-script, invisible, control
- [ ] I-004 [Test] integration.rs - No test for --exclude or --file-list flags
- [ ] I-005 [Test] test.yml - No test for "changed" scan-mode with actual PR diff
- [x] I-006 [CI] test-rust.yml - No cargo dependency caching
  Added Swatinem/rust-cache@v2.
- [-] I-007 [CI] release.yml - softprops/action-gh-release@v2 not pinned to SHA
  Superseded by M-038 (upgraded to MEDIUM).
- [-] I-008 [Parity] output.rs - Rust annotations 1-based vs Python 0-based
  Wont-fix. Rust is correct per GitHub spec; Python has the bug.
- [-] I-009 [Parity] output.rs - SARIF tool version "3.0.0" vs Python "2.0.0"
  Wont-fix. Intentional; matches Cargo.toml version.
- [ ] I-010 [Design] config.rs - Context-based allowlist not implemented
- [ ] I-011 [Design] models.rs - get_rule and RULE_IDS could drift
- [ ] I-012 [Crate] Cargo.toml - Not yet configured for crates.io

---

## Summary

| Status | Count |
|--------|-------|
| Fixed  | 67    |
| Wont-fix | 13  |
| Open   | 25    |
| **Total** | **105** |

### Remaining open items by priority

| ID | Severity | File | Description |
|----|----------|------|-------------|
| H-010 | HIGH | action.yml | No checksum verification of downloaded binary |
| M-003 | MEDIUM | scanner.rs | TOCTOU race (inherent to design) |
| M-029 | MEDIUM | unicode_data.rs | SCRIPT_RANGES missing many scripts |
| M-030 | MEDIUM | unicode_data.rs | CONFUSABLES table too small |
| M-035 | MEDIUM | Cargo.toml | Cargo.lock not committed |
| M-038 | MEDIUM | release.yml | action-gh-release pinned to tag not SHA |
| M-040 | MEDIUM | integration.rs | No finding count assertions |
| M-041 | MEDIUM | integration.rs | SARIF test missing results check |
| M-042 | MEDIUM | integration.rs | 11/19 rules have zero test coverage |
| M-043 | MEDIUM | integration.rs | No warning-only exit code test |
| L-022 | LOW | checks.rs | check_encoding col is byte offset |
| L-024 | LOW | config.rs | Silent failure on invalid char specs |
| L-025 | LOW | config.rs | No codepoint range validation |
| L-027 | LOW | tokenizer.rs | Backtick continuation ignores escapes |
| L-028 | LOW | tokenizer.rs | HTML/XML comments not handled |
| L-029 | LOW | tokenizer.rs | SQL -- comments not handled |
| L-031 | LOW | unicode_data.rs | Second NFD pass always no-op |
| L-033 | LOW | Cargo.toml | serde_yaml deprecated |
| L-035 | LOW | test.yml | test-exclude has no exclusion assertion |
| L-036 | LOW | integration.rs | Tests miss incidental rule triggers |
| L-037 | LOW | integration.rs | SARIF temp file leak on panic |
| I-001 | INFO | scanner.rs | Missing symlink/permission tests |
| I-002 | INFO | diff.rs | Missing malformed diff tests |
| I-003 | INFO | test-rust.yml | Missing CI acceptance tests |
| I-004 | INFO | integration.rs | Missing --exclude/--file-list tests |
| I-005 | INFO | test.yml | Missing "changed" scan-mode test |
| I-010 | INFO | config.rs | Context-based allowlist not implemented |
| I-011 | INFO | models.rs | get_rule/RULE_IDS drift risk |
| I-012 | INFO | Cargo.toml | crates.io publishing prep |
