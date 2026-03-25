"""Git diff parsing for diff-aware scanning."""

import re
import subprocess
from typing import Dict, Optional, Set


def get_changed_lines(base_sha: Optional[str] = None) -> Dict[str, Set[int]]:
    """Parse git diff to find newly added/modified lines per file.

    Returns a dict mapping file paths to sets of line numbers that were
    added or modified. Only these lines need strict checking.
    """
    if base_sha is None:
        return {}

    try:
        result = subprocess.run(
            ["git", "diff", "-U0", "--diff-filter=AMR", base_sha, "HEAD"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return {}
        return parse_unified_diff(result.stdout)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {}


def parse_unified_diff(diff_text: str) -> Dict[str, Set[int]]:
    """Parse unified diff output into file -> changed line numbers."""
    result: Dict[str, Set[int]] = {}
    current_file = None

    for line in diff_text.splitlines():
        # New file header: +++ b/path/to/file
        if line.startswith("+++ b/"):
            current_file = line[6:]
            if current_file not in result:
                result[current_file] = set()
        # Hunk header: @@ -old,count +new,count @@
        elif line.startswith("@@") and current_file:
            match = re.search(r'\+(\d+)(?:,(\d+))?', line)
            if match:
                start = int(match.group(1))
                count = int(match.group(2)) if match.group(2) else 1
                for i in range(start, start + count):
                    result[current_file].add(i)

    return result


def get_changed_files(base_sha: Optional[str] = None) -> list:
    """Get list of changed file paths."""
    if base_sha is None:
        return []

    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=AMR", base_sha, "HEAD"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return []
        return [f.strip() for f in result.stdout.splitlines() if f.strip()]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []
