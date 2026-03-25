#!/usr/bin/env bash
# entrypoint.sh -- Unicode safety scanner for GitHub Actions.
#
# Detects adversarial Unicode in source files: invisible characters, bidi
# overrides, Private Use Area code points, tag characters, variation selectors,
# homoglyphs, and encoding issues.
#
# Inputs (via environment variables set by action.yml):
#   INPUT_EXCLUDE_PATTERNS    - newline-separated path exclusion regexes
#   INPUT_ALLOWLIST_FILE      - path to per-line Perl regex allowlist
#   INPUT_FAIL_ON_WARN        - "true" to treat warnings as errors
#   INPUT_DISABLE_HOMOGLYPHS  - "true" to skip homoglyph detection
#   INPUT_DISABLE_ANNOTATIONS - "true" to skip GitHub PR annotations
#   INPUT_SARIF_FILE          - path to write SARIF output (empty = no SARIF)
#
# Usage:
#   entrypoint.sh <file-list>   # one path per line
#   entrypoint.sh --all         # scan entire repo
#
# Exit codes: 0 = clean, 1 = findings, 2 = usage error

set -eo pipefail

# ---------------------------------------------------------------------------
# Default exclusions (binary, build output, dependency dirs)
# ---------------------------------------------------------------------------

DEFAULT_EXCLUDE_PATTERNS=(
  '\.git/'
  'node_modules/'
  '\.vscode/'
  '__pycache__/'
  '\.mypy_cache/'
  '\.tox/'
  'vendor/'
  'dist/'
  'build/'
  '_site/'
  '\.next/'
  'target/'
  '\.woff2?$'
  '\.ttf$'
  '\.otf$'
  '\.eot$'
  '\.png$'
  '\.jpe?g$'
  '\.gif$'
  '\.ico$'
  '\.svg$'
  '\.pdf$'
  '\.wasm$'
  '\.pyc$'
  '\.class$'
  '\.o$'
  '\.so$'
  '\.dylib$'
  '\.dll$'
  '\.exe$'
  '\.a$'
  '\.lib$'
  '\.jar$'
  '\.war$'
  '\.zip$'
  '\.tar'
  '\.gz$'
  '\.bz2$'
  '\.xz$'
  '\.7z$'
  '\.rar$'
  '\.lock$'
  '\.min\.js$'
  '\.min\.css$'
  '\.map$'
  '\.pb\.go$'
  '_generated\.'
  '\.generated\.'
)

# ---------------------------------------------------------------------------
# Merge user-provided exclusions
# ---------------------------------------------------------------------------

EXCLUDE_PATTERNS=("${DEFAULT_EXCLUDE_PATTERNS[@]}")
if [ -n "${INPUT_EXCLUDE_PATTERNS:-}" ]; then
  while IFS= read -r pat; do
    [ -n "$pat" ] && EXCLUDE_PATTERNS+=("$pat")
  done <<< "$INPUT_EXCLUDE_PATTERNS"
fi

# ---------------------------------------------------------------------------
# Allowlist
# ---------------------------------------------------------------------------

ALLOWLIST_FILE="${INPUT_ALLOWLIST_FILE:-}"
ALLOWLIST_ENTRIES=()

load_allowlist() {
  if [ -n "$ALLOWLIST_FILE" ] && [ -f "$ALLOWLIST_FILE" ]; then
    while IFS= read -r line; do
      [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
      ALLOWLIST_ENTRIES+=("$line")
    done < "$ALLOWLIST_FILE"
  fi
}

is_allowlisted() {
  local text="$1"
  if [ "${#ALLOWLIST_ENTRIES[@]}" -eq 0 ]; then
    return 1
  fi
  for pattern in "${ALLOWLIST_ENTRIES[@]}"; do
    if echo "$text" | perl -ne "exit 0 if /$pattern/; exit 1" 2>/dev/null; then
      return 0
    fi
  done
  return 1
}

# ---------------------------------------------------------------------------
# Character class regexes (Perl-compatible Unicode escapes)
# ---------------------------------------------------------------------------

# Zero-width and invisible formatting characters
INVISIBLE_RE='[\x{200B}\x{200C}\x{200D}\x{2060}\x{180E}\x{00AD}]'

# Bidirectional override / embedding / isolate controls
BIDI_RE='[\x{202A}-\x{202E}\x{2066}-\x{2069}\x{200E}\x{200F}\x{061C}]'

# Private Use Area (BMP + supplementary planes)
PUA_RE='[\x{E000}-\x{F8FF}\x{F0000}-\x{FFFFD}\x{100000}-\x{10FFFD}]'

# Tag characters (U+E0001-U+E007F) -- Glassworm-style payload encoding
TAG_RE='[\x{E0001}-\x{E007F}]'

# Variation selectors -- standard (U+FE00-FE0F) and supplement (U+E0100-E01EF)
# Used by Glassworm to encode payloads as invisible modifier sequences
VARIATION_RE='[\x{FE00}-\x{FE0F}\x{E0100}-\x{E01EF}]'

# Interlinear annotation anchors
ANNOTATION_RE='[\x{FFF9}-\x{FFFB}]'

# Deprecated format characters
DEPRECATED_RE='[\x{206A}-\x{206F}\x{FFF0}-\x{FFF8}]'

# Cyrillic/Greek homoglyphs for Latin letters
HOMOGLYPH_RE='[\x{0410}\x{0430}\x{0421}\x{0441}\x{0415}\x{0435}\x{041D}\x{043D}\x{041E}\x{043E}\x{0420}\x{0440}\x{0405}\x{0455}\x{0406}\x{0456}\x{0408}\x{0458}\x{042C}\x{044C}\x{0425}\x{0445}\x{0423}\x{0443}\x{0392}\x{03B2}\x{0393}\x{03B3}\x{0395}\x{03B5}\x{0397}\x{03B7}\x{039F}\x{03BF}\x{03A1}\x{03C1}\x{03A4}\x{03C4}\x{03A5}\x{03C5}]'

# ---------------------------------------------------------------------------
# Rule metadata (for SARIF output)
# ---------------------------------------------------------------------------

# Parallel arrays: rule ID, short description, help text, severity (error/warning)
RULE_IDS=(
  "USC001" "USC002" "USC003" "USC004" "USC005"
  "USC006" "USC007" "USC008" "USC009" "USC010"
)
RULE_NAMES=(
  "bidi-override" "private-use" "tag-chars" "invisible-char" "misplaced-bom"
  "annotation" "deprecated-fmt" "homoglyph" "invalid-utf8" "variation-selector"
)
RULE_DESCS=(
  "Bidirectional text override or isolate control character detected"
  "Private Use Area code point detected"
  "Tag character detected (Glassworm-style payload encoding)"
  "Invisible formatting character detected (zero-width space/joiner)"
  "Byte-order mark found after start of file"
  "Interlinear annotation anchor detected"
  "Deprecated Unicode format character detected"
  "Cyrillic/Greek homoglyph for Latin letter detected"
  "File contains invalid UTF-8 byte sequences"
  "Variation selector detected (potential invisible payload encoding)"
)
RULE_HELP=(
  "Bidi override characters (U+202A-202E, U+2066-2069) can reorder displayed text, making code or spec text appear to say one thing while its logical content says another. See CVE-2021-42574 (Trojan Source)."
  "Private Use Area code points (U+E000-F8FF, U+F0000-10FFFD) have no standard meaning and can be used to smuggle data through text that appears blank."
  "Tag characters (U+E0001-E007F) map to ASCII letters but render as invisible. Used by the Glassworm campaign (2026) to encode malicious payloads that evade review and static analysis."
  "Zero-width characters (U+200B, U+200C, U+200D, U+2060) are invisible but make strings that look identical compare as different, breaking validation and identifier matching."
  "A byte-order mark (U+FEFF) after the start of a file serves no legitimate purpose and may indicate content injection or encoding manipulation."
  "Interlinear annotation anchors (U+FFF9-FFFB) can hide content between visible text. These characters have no standard rendering and should not appear in source files."
  "Deprecated format characters (U+206A-206F) are officially discouraged by Unicode and have no legitimate use in modern text."
  "Characters from Cyrillic or Greek scripts that are visually identical to Latin letters can spoof identifiers, URIs, or other security-sensitive strings."
  "Files must be valid UTF-8. Invalid byte sequences may indicate encoding corruption, content injection, or parser confusion attacks."
  "Variation selectors (U+FE00-FE0F, U+E0100-E01EF) modify preceding characters but can encode hidden payloads when chained. Used in Glassworm-style attacks to create invisible executable content."
)
RULE_SEVERITIES=(
  "error" "error" "error" "error" "error"
  "error" "error" "warning" "error" "error"
)

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

findings=0
errors=0
warnings=0
files_checked=0

FAIL_ON_WARN="${INPUT_FAIL_ON_WARN:-false}"
DISABLE_HOMOGLYPHS="${INPUT_DISABLE_HOMOGLYPHS:-false}"
DISABLE_ANNOTATIONS="${INPUT_DISABLE_ANNOTATIONS:-false}"
SARIF_FILE="${INPUT_SARIF_FILE:-}"

# Collect SARIF results as JSON fragments
SARIF_RESULTS=""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

should_exclude() {
  local file="$1"
  for pat in "${EXCLUDE_PATTERNS[@]}"; do
    if [[ "$file" =~ $pat ]]; then
      return 0
    fi
  done
  return 1
}

# Escape a string for safe embedding in JSON
json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/\\r}"
  s="${s//$'\t'/\\t}"
  # Strip control characters that would break JSON
  s=$(echo "$s" | tr -d '\000-\010\013\014\016-\037')
  echo "$s"
}

# Record a finding. Emits annotation + collects SARIF result.
# Args: rule_index file lineno content
record_finding() {
  local rule_idx="$1"
  local file="$2"
  local lineno="$3"
  local content="$4"

  local rule_id="${RULE_IDS[$rule_idx]}"
  local rule_name="${RULE_NAMES[$rule_idx]}"
  local severity="${RULE_SEVERITIES[$rule_idx]}"
  local desc="${RULE_DESCS[$rule_idx]}"

  # Truncate content for display
  if [ "${#content}" -gt 120 ]; then
    content="${content:0:120}..."
  fi

  local msg="$desc: $content"

  # GitHub annotation
  if [ "$DISABLE_ANNOTATIONS" != "true" ]; then
    echo "::${severity} file=${file},line=${lineno},title=Unicode Safety [${rule_name}]::${msg}"
  fi

  # Counters
  if [ "$severity" = "error" ]; then
    errors=$((errors + 1))
  else
    warnings=$((warnings + 1))
  fi
  findings=$((findings + 1))

  # SARIF result fragment
  if [ -n "$SARIF_FILE" ]; then
    local escaped_msg
    escaped_msg=$(json_escape "$msg")
    local escaped_file
    escaped_file=$(json_escape "$file")
    # Remove leading ./ from file paths for SARIF
    escaped_file="${escaped_file#./}"

    local sarif_level="error"
    if [ "$severity" = "warning" ] || [ "$severity" = "warn" ]; then
      sarif_level="warning"
    fi

    local result
    result=$(cat <<SARIF_RESULT_EOF
    {
      "ruleId": "${rule_id}",
      "level": "${sarif_level}",
      "message": { "text": "${escaped_msg}" },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": { "uri": "${escaped_file}", "uriBaseId": "%SRCROOT%" },
          "region": { "startLine": ${lineno} }
        }
      }]
    }
SARIF_RESULT_EOF
    )

    if [ -n "$SARIF_RESULTS" ]; then
      SARIF_RESULTS="${SARIF_RESULTS},
${result}"
    else
      SARIF_RESULTS="$result"
    fi
  fi
}

# Look up rule index by name
rule_index_for() {
  local name="$1"
  for i in "${!RULE_NAMES[@]}"; do
    if [ "${RULE_NAMES[$i]}" = "$name" ]; then
      echo "$i"
      return
    fi
  done
  echo "0"
}

check_pattern() {
  local label="$1"
  local severity="$2"
  local regex="$3"
  local file="$4"

  local rule_idx
  rule_idx=$(rule_index_for "$label")

  local hits
  hits=$(perl -CSD -ne '
    if (/'$regex'/) {
      print "$.:$_";
    }
  ' "$file" 2>/dev/null) || true

  if [ -n "$hits" ]; then
    while IFS= read -r hit; do
      if ! is_allowlisted "$hit"; then
        local lineno="${hit%%:*}"
        local content="${hit#*:}"
        record_finding "$rule_idx" "$file" "$lineno" "$content"
      fi
    done <<< "$hits"
  fi
}

check_bom_misplaced() {
  local file="$1"
  local rule_idx
  rule_idx=$(rule_index_for "misplaced-bom")

  local hits
  hits=$(perl -CSD -ne '
    if ($. == 1) {
      s/^\x{FEFF}//;
    }
    if (/\x{FEFF}/) {
      print "$.:$_";
    }
  ' "$file" 2>/dev/null) || true

  if [ -n "$hits" ]; then
    while IFS= read -r hit; do
      if ! is_allowlisted "$hit"; then
        local lineno="${hit%%:*}"
        record_finding "$rule_idx" "$file" "$lineno" "Byte-order mark found after start of file"
      fi
    done <<< "$hits"
  fi
}

check_encoding() {
  local file="$1"

  if ! iconv -f UTF-8 -t UTF-8 "$file" > /dev/null 2>&1; then
    local rule_idx
    rule_idx=$(rule_index_for "invalid-utf8")
    record_finding "$rule_idx" "$file" "1" "File contains invalid UTF-8 byte sequences"
  fi
}

# Variation selector context check: flag sequences of 3+ variation selectors,
# which indicate payload encoding rather than legitimate emoji/glyph use.
check_variation_selectors() {
  local file="$1"
  local rule_idx
  rule_idx=$(rule_index_for "variation-selector")

  local hits
  hits=$(perl -CSD -ne '
    # Flag lines with 3+ variation selectors (legitimate use is 1 per base char)
    my @vs = /[\x{FE00}-\x{FE0F}\x{E0100}-\x{E01EF}]/g;
    if (@vs >= 3) {
      print "$.:$_";
    }
  ' "$file" 2>/dev/null) || true

  if [ -n "$hits" ]; then
    while IFS= read -r hit; do
      if ! is_allowlisted "$hit"; then
        local lineno="${hit%%:*}"
        local content="${hit#*:}"
        record_finding "$rule_idx" "$file" "$lineno" "$content"
      fi
    done <<< "$hits"
  fi
}

scan_file() {
  local file="$1"

  if should_exclude "$file"; then
    return
  fi

  # Skip binary files
  if file -b --mime-type "$file" 2>/dev/null | grep -qv '^text/'; then
    return
  fi

  files_checked=$((files_checked + 1))

  check_encoding "$file"
  check_pattern "bidi-override"   "error" "$BIDI_RE"       "$file"
  check_pattern "private-use"     "error" "$PUA_RE"        "$file"
  check_pattern "tag-chars"       "error" "$TAG_RE"        "$file"
  check_pattern "invisible-char"  "error" "$INVISIBLE_RE"  "$file"
  check_bom_misplaced "$file"
  check_pattern "annotation"      "error" "$ANNOTATION_RE" "$file"
  check_pattern "deprecated-fmt"  "error" "$DEPRECATED_RE" "$file"
  check_variation_selectors "$file"

  if [ "$DISABLE_HOMOGLYPHS" != "true" ]; then
    check_pattern "homoglyph"     "warn"  "$HOMOGLYPH_RE"  "$file"
  fi
}

# ---------------------------------------------------------------------------
# SARIF output
# ---------------------------------------------------------------------------

write_sarif() {
  if [ -z "$SARIF_FILE" ]; then
    return
  fi

  # Build rules array
  local rules=""
  for i in "${!RULE_IDS[@]}"; do
    local escaped_desc
    escaped_desc=$(json_escape "${RULE_DESCS[$i]}")
    local escaped_help
    escaped_help=$(json_escape "${RULE_HELP[$i]}")
    local sarif_level="error"
    if [ "${RULE_SEVERITIES[$i]}" = "warning" ] || [ "${RULE_SEVERITIES[$i]}" = "warn" ]; then
      sarif_level="warning"
    fi

    local rule
    rule=$(cat <<RULE_EOF
      {
        "id": "${RULE_IDS[$i]}",
        "name": "${RULE_NAMES[$i]}",
        "shortDescription": { "text": "${escaped_desc}" },
        "fullDescription": { "text": "${escaped_help}" },
        "helpUri": "https://github.com/dcondrey/unicode-safety-check#what-it-detects",
        "defaultConfiguration": { "level": "${sarif_level}" },
        "properties": { "tags": ["security", "unicode", "supply-chain"] }
      }
RULE_EOF
    )

    if [ -n "$rules" ]; then
      rules="${rules},
${rule}"
    else
      rules="$rule"
    fi
  done

  cat > "$SARIF_FILE" <<SARIF_EOF
{
  "\$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "unicode-safety-check",
        "informationUri": "https://github.com/dcondrey/unicode-safety-check",
        "version": "1.0.0",
        "rules": [
${rules}
        ]
      }
    },
    "results": [
${SARIF_RESULTS}
    ]
  }]
}
SARIF_EOF

  echo "SARIF report written to: $SARIF_FILE"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if [ $# -lt 1 ]; then
  echo "Usage: $0 <file-list> | --all"
  exit 2
fi

load_allowlist

if [ "$1" = "--all" ]; then
  while IFS= read -r -d '' file; do
    scan_file "$file"
  done < <(find . -type f -print0)
else
  file_list="$1"
  if [ ! -f "$file_list" ]; then
    echo "Error: file list not found: $file_list"
    exit 2
  fi
  while IFS= read -r file; do
    [ -f "$file" ] && scan_file "$file"
  done < "$file_list"
fi

# ---------------------------------------------------------------------------
# Summary & outputs
# ---------------------------------------------------------------------------

echo ""
echo "Unicode safety check complete: $files_checked files scanned, $findings finding(s) ($errors error(s), $warnings warning(s))."

write_sarif

# Set outputs for downstream steps
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "findings=$findings" >> "$GITHUB_OUTPUT"
  echo "files_scanned=$files_checked" >> "$GITHUB_OUTPUT"
  if [ -n "$SARIF_FILE" ]; then
    echo "sarif_file=$SARIF_FILE" >> "$GITHUB_OUTPUT"
  fi
fi

# Write job summary
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### Unicode Safety Check"
    echo ""
    echo "| Metric | Count |"
    echo "|--------|-------|"
    echo "| Files scanned | $files_checked |"
    echo "| Errors | $errors |"
    echo "| Warnings | $warnings |"
    echo ""
    if [ "$findings" -eq 0 ]; then
      echo "No adversarial Unicode detected."
    fi
  } >> "$GITHUB_STEP_SUMMARY"
fi

# Determine exit code
if [ "$errors" -gt 0 ]; then
  exit 1
elif [ "$FAIL_ON_WARN" = "true" ] && [ "$warnings" -gt 0 ]; then
  exit 1
else
  exit 0
fi
