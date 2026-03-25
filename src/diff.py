"""Git diff parsing for diff-aware scanning."""
import re
import subprocess


def get_changed_lines(base_sha=None):
    if not base_sha:
        return {}
    try:
        r = subprocess.run(["git", "diff", "-U0", "--diff-filter=AMR", base_sha, "HEAD"],
                           capture_output=True, text=True, timeout=30)
        return _parse_diff(r.stdout) if r.returncode == 0 else {}
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {}


def _parse_diff(text):
    result = {}
    cur = None
    for line in text.splitlines():
        if line.startswith("+++ b/"):
            cur = line[6:]
            result.setdefault(cur, set())
        elif line.startswith("@@") and cur:
            m = re.search(r'\+(\d+)(?:,(\d+))?', line)
            if m:
                start = int(m.group(1))
                count = int(m.group(2)) if m.group(2) else 1
                result[cur].update(range(start, start + count))
    return result
