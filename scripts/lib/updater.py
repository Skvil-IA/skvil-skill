"""Auto-update check for skvil — pulls latest version if behind remote.

Runs at most once per hour (controlled by a timestamp marker file).
All failures are silent — network errors, git errors, permission issues
never block the scanner from running with the current version.
"""

import os
import subprocess
import sys
import time

# Check at most once per hour
_CHECK_INTERVAL = 3600
_MARKER_FILE = os.path.join(os.path.expanduser("~"), ".skvil", "last_update_check")


def _should_check() -> bool:
    """Return True if enough time has passed since the last check."""
    try:
        if os.path.exists(_MARKER_FILE):
            mtime = os.path.getmtime(_MARKER_FILE)
            if time.time() - mtime < _CHECK_INTERVAL:
                return False
    except OSError:
        pass
    return True


def _touch_marker() -> None:
    """Update the marker file timestamp."""
    try:
        marker_dir = os.path.dirname(_MARKER_FILE)
        os.makedirs(marker_dir, exist_ok=True)
        with open(_MARKER_FILE, "w") as f:
            f.write(str(int(time.time())))
    except OSError:
        pass


def auto_update(skvil_dir: str) -> None:
    """Check for updates and pull if behind. Silent on all errors.

    Args:
        skvil_dir: Path to the skvil skill root directory (contains .git/).
    """
    if not _should_check():
        return

    git_dir = os.path.join(skvil_dir, ".git")
    if not os.path.isdir(git_dir):
        return

    _touch_marker()

    try:
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/tmp"),
            "GIT_TERMINAL_PROMPT": "0",
        }
        for k in ("LANG", "LC_ALL", "LC_CTYPE"):
            if k in os.environ:
                env[k] = os.environ[k]

        # Fetch latest (5s timeout — don't block the scan)
        fetch = subprocess.run(
            ["git", "-C", skvil_dir, "fetch", "--quiet"],
            capture_output=True,
            timeout=5,
            env=env,
        )
        if fetch.returncode != 0:
            return

        # Check if behind
        status = subprocess.run(
            ["git", "-C", skvil_dir, "status", "-uno", "--porcelain=v2", "--branch"],
            capture_output=True,
            text=True,
            timeout=5,
            env=env,
        )
        if status.returncode != 0:
            return

        behind = False
        for line in status.stdout.splitlines():
            if line.startswith("# branch.ab"):
                # Format: # branch.ab +ahead -behind
                parts = line.split()
                if len(parts) >= 4:
                    behind_count = int(parts[3])  # negative number
                    behind = behind_count < 0
                break

        if not behind:
            return

        # Pull (fast-forward only — never creates merge commits)
        pull = subprocess.run(
            ["git", "-C", skvil_dir, "pull", "--ff-only", "--quiet"],
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
        )
        if pull.returncode == 0:
            print("[skvil] updated to latest version", file=sys.stderr)

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError, ValueError):
        pass
