#!/usr/bin/env python3
"""Skvil Check — Analyze a skill from a URL before installing it."""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import traceback

# Add parent directory to path so lib can be imported
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pathlib import Path

from lib.client import get_verify, load_config, merge_reputation, merge_verify, post_scan
from lib.collector import collect_skill, is_contained
from lib.formatter import compute_score, format_check_output, format_skill_result, risk_level, to_json
from lib.hasher import composite_hash, hash_directory, skvil_kedavra_self_hash
from lib.patterns import scan_binary_presence, scan_oversized_files, scan_skill

_SKVIL_KEDAVRA_DIR = str(Path(os.path.abspath(__file__)).parent.parent.resolve())

# Limits
CLONE_TIMEOUT = 30  # seconds
MAX_REPO_SIZE_MB = 50


ALLOWED_HOSTS = {"github.com", "gitlab.com", "bitbucket.org"}


def normalize_url(url: str) -> str:
    """Normalize a git hosting URL to a clonable HTTPS URL.

    Handles all ALLOWED_HOSTS (H3 fix), not just GitHub.
    Accepts shorthand (user/repo → github.com), host/user/repo, or full HTTPS URLs.
    Rejects SSH URLs and non-allowed hosts.
    """
    url = url.strip().rstrip("/")

    # Handle shorthand: user/repo → default to GitHub
    if re.match(r"^[a-zA-Z][\w.-]*/[a-zA-Z][\w.-]*$", url):
        url = f"https://github.com/{url}"
    else:
        # Handle host/user/repo without https:// prefix (all allowed hosts)
        for host in ALLOWED_HOSTS:
            if re.match(rf"^{re.escape(host)}/[a-zA-Z][\w.-]*/[a-zA-Z][\w.-]*/?$", url):
                url = f"https://{url}"
                break

    # Ensure .git suffix for cloning (all allowed hosts)
    for host in ALLOWED_HOSTS:
        if url.startswith(f"https://{host}/") and not url.endswith(".git"):
            url = url + ".git"
            break

    return url


def validate_url(url: str) -> bool:
    """Validate that URL is a safe HTTPS git URL.

    Rejects SSH URLs (git@) to avoid credential prompts and hangs.
    Only allows HTTPS to known git hosting providers.
    """
    if not url.startswith("https://"):
        return False
    # Block URLs with credentials embedded
    host_part = url.split("//")[1].split("/")[0]
    if "@" in host_part:
        return False
    # Allowlist of trusted hosts
    return host_part in ALLOWED_HOSTS


def clone_repo(url: str, dest: str) -> bool:
    """Clone a repo with depth 1, hooks disabled, to minimize risk.

    SECURITY: Disables git hooks to prevent arbitrary code execution
    from malicious repositories during clone.
    """
    # Create an empty directory as hooks path — cross-platform (M1 fix).
    # /dev/null does not exist on Windows, so git would silently fall back
    # to the default hooks path, leaving hooks enabled.
    hooks_dir = tempfile.mkdtemp(prefix="skvil-nohooks-")
    try:
        # Minimal environment to prevent GIT_CONFIG_*, LD_PRELOAD, etc. from
        # bypassing git safety measures
        clone_env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", tempfile.gettempdir()),
            "GIT_TEMPLATE_DIR": "",
            "GIT_TERMINAL_PROMPT": "0",
        }
        for k in ("LANG", "LC_ALL", "LC_CTYPE", "SYSTEMROOT", "COMSPEC"):
            if k in os.environ:
                clone_env[k] = os.environ[k]
        result = subprocess.run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                "--single-branch",
                "--config",
                f"core.hooksPath={hooks_dir}",
                url,
                dest,
            ],
            capture_output=True,
            text=True,
            timeout=CLONE_TIMEOUT,
            env=clone_env,
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except FileNotFoundError:
        print(
            to_json(
                {
                    "type": "check",
                    "error": "git is not installed. Install git to use skvil check.",
                }
            )
        )
        sys.exit(1)
    finally:
        shutil.rmtree(hooks_dir, ignore_errors=True)


def find_skill_root(repo_dir: str) -> str:
    """Find the skill root directory within a cloned repo.

    The SKILL.md might be at the root or in a subdirectory.
    Validates that any discovered subdirectory stays within repo_dir to
    prevent symlink-based path traversal (e.g. a subdir symlink pointing outside the tmp clone).
    Uses is_contained() for cross-platform containment check (M3 fix).
    """
    repo_root = Path(repo_dir)

    # Check root first
    if os.path.exists(os.path.join(repo_dir, "SKILL.md")):
        return repo_dir

    # Check one level deep — resolve symlinks and validate containment
    for entry in sorted(os.listdir(repo_dir)):
        subdir = repo_root / entry
        if subdir.is_dir() and os.path.exists(subdir / "SKILL.md"):
            if is_contained(subdir, repo_root):
                return str(subdir.resolve())

    return repo_dir  # Fallback to root even without SKILL.md


def check_skill(url: str):
    """Clone and analyze a skill from a URL."""
    normalized = normalize_url(url)

    if not validate_url(normalized):
        print(
            to_json(
                {
                    "type": "check",
                    "url": url,
                    "error": "Invalid URL. Provide an HTTPS GitHub URL like github.com/user/skill",
                }
            )
        )
        return

    # Create temp parent, let git create the subdirectory
    tmp_parent = tempfile.mkdtemp(prefix="skvil-check-")
    tmp_dir = os.path.join(tmp_parent, "repo")

    try:
        # Clone
        if not clone_repo(normalized, tmp_dir):
            print(
                to_json(
                    {
                        "type": "check",
                        "url": url,
                        "error": "Failed to clone repository. Check the URL and try again.",
                    }
                )
            )
            return

        # Check repo size (post-clone — timeout limits download)
        total_size = 0
        for dirpath, _, filenames in os.walk(tmp_dir):
            for f in filenames:
                fpath = os.path.join(dirpath, f)
                if not os.path.islink(fpath):
                    total_size += os.path.getsize(fpath)
        if total_size > MAX_REPO_SIZE_MB * 1024 * 1024:
            print(
                to_json(
                    {
                        "type": "check",
                        "url": url,
                        "error": f"Repository too large ({total_size // (1024 * 1024)}MB). Max: {MAX_REPO_SIZE_MB}MB.",
                    }
                )
            )
            return

        # Find skill root
        skill_root = find_skill_root(tmp_dir)

        # Collect metadata and code
        skill_data = collect_skill(skill_root)

        # Compute hashes
        file_hashes = hash_directory(skill_root)
        comp_hash = composite_hash(file_hashes)

        # Run pattern detection
        findings = (
            scan_skill(skill_data["code_snippets"])
            + scan_binary_presence(skill_data["files"])
            + scan_oversized_files(skill_data["oversized_code_files"])
        )

        # Format result
        result = format_skill_result(
            name=skill_data["name"],
            path=url,
            composite_hash=comp_hash,
            file_hashes=file_hashes,
            findings=findings,
            frontmatter=skill_data["frontmatter"],
        )

        # Check if SKILL.md exists — recompute score with the extra finding (M10 fix)
        has_skill_md = os.path.exists(os.path.join(skill_root, "SKILL.md"))
        if not has_skill_md:
            result["findings"].insert(
                0,
                {
                    "severity": "high",
                    "category": "metadata",
                    "description": "No SKILL.md found — skill does not follow Agent Skills standard",
                    "file": "SKILL.md",
                    "line": 0,
                },
            )
            result["score"] = compute_score(result["findings"])
            result["risk_level"] = risk_level(result["score"])

        # Submit scan to backend (auto-registers if needed), fall back to public verify
        config = load_config()
        reputation = post_scan(result, config, skill_url=normalized)
        if reputation:
            merge_reputation(result, reputation)
            mode = "connected"
        else:
            verification = get_verify(result["composite_hash"], config)
            if verification:
                merge_verify(result, verification)
            mode = "connected" if verification else "local"

        output = format_check_output(url, result)
        output["mode"] = mode
        output["skvil_kedavra_hash"] = skvil_kedavra_self_hash(_SKVIL_KEDAVRA_DIR)
        print(to_json(output))

    except Exception as e:
        traceback.print_exc(file=sys.stderr)
        print(
            to_json(
                {
                    "type": "check",
                    "url": url,
                    "error": f"Analysis failed: {e}",
                }
            )
        )

    finally:
        # Always clean up
        shutil.rmtree(tmp_parent, ignore_errors=True)


def main():
    if len(sys.argv) < 2:
        print(
            to_json(
                {
                    "type": "check",
                    "error": "Usage: skvil_kedavra_check.py <github-url>",
                }
            )
        )
        sys.exit(1)

    url = sys.argv[1]
    check_skill(url)


if __name__ == "__main__":
    main()
