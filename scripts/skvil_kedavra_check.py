#!/usr/bin/env python3
"""Skvil Check — Analyze a skill from a URL before installing it."""

import os
import re
import shutil
import subprocess
import sys
import tempfile

# Add parent directory to path so lib can be imported
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pathlib import Path

from lib.client import get_verify, load_config, merge_reputation, merge_verify, post_scan
from lib.collector import collect_skill
from lib.formatter import format_check_output, format_skill_result, to_json
from lib.hasher import composite_hash, hash_directory, skvil_kedavra_self_hash
from lib.patterns import scan_binary_presence, scan_oversized_files, scan_skill

_SKVIL_KEDAVRA_DIR = str(Path(os.path.abspath(__file__)).parent.parent.resolve())

# Limits
CLONE_TIMEOUT = 30  # seconds
MAX_REPO_SIZE_MB = 50


def parse_monorepo_url(url: str):
    """Parse a GitHub URL that may point to a subdirectory within a monorepo.

    Returns (clone_url, subdir) where subdir is None for regular repos.

    Supports:
      https://github.com/user/repo                                → (clone_url, None)
      https://github.com/user/repo/tree/main/skill-name           → (clone_url, "skill-name")
      https://github.com/user/repo/tree/main/a/b                  → (clone_url, "a/b")
      https://github.com/user/repo/blob/main/skill-name/SKILL.md  → (clone_url, "skill-name")
    """
    url = url.strip().rstrip("/")

    # Normalize shorthand and bare github.com URLs first
    if re.match(r"^[a-zA-Z][\w.-]*/[a-zA-Z][\w.-]*$", url):
        url = f"https://github.com/{url}"
    elif re.match(r"^github\.com/", url):
        url = f"https://{url}"

    # Extract /tree/branch/path or /blob/branch/path if present
    m = re.match(r"^(https://[^/]+/[^/]+/[^/]+)/(?:tree|blob)/[^/]+/(.+)$", url)
    if m:
        repo_url = m.group(1)
        subdir = m.group(2).strip("/")
        # Strip trailing filename (e.g. SKILL.md, README.md) — keep only the directory
        parts = subdir.split("/")
        if "." in parts[-1]:
            parts = parts[:-1]
        subdir = "/".join(parts) if parts else None
        # Validate subdir: no path traversal
        if subdir and ".." in subdir.split("/"):
            subdir = None
        return repo_url, subdir

    # Strip /tree/branch or /blob/branch with no subpath (just pointing at a branch)
    url = re.sub(r"/(?:tree|blob)/[^/]+/?$", "", url)

    return url, None


def normalize_url(url: str) -> str:
    """Normalize a GitHub URL to a clonable HTTPS URL.

    Only accepts HTTPS GitHub URLs or shorthand (user/repo).
    Rejects SSH URLs and non-GitHub hosts.
    Strips /tree/branch/path for cloning — use parse_monorepo_url() to get subdirs.
    """
    repo_url, _ = parse_monorepo_url(url)

    # Ensure .git suffix for cloning
    if repo_url.startswith("https://github.com/") and not repo_url.endswith(".git"):
        repo_url = repo_url + ".git"

    return repo_url


ALLOWED_HOSTS = {"github.com", "gitlab.com", "bitbucket.org"}


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
    try:
        # Minimal environment to prevent GIT_CONFIG_*, LD_PRELOAD, etc. from
        # bypassing git safety measures
        clone_env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/tmp"),
            "GIT_TEMPLATE_DIR": "",
            "GIT_TERMINAL_PROMPT": "0",
        }
        for k in ("LANG", "LC_ALL", "LC_CTYPE"):
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
                "core.hooksPath=/dev/null",
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


def find_skill_root(repo_dir: str):
    """Find the skill root directory within a cloned repo.

    Returns (skill_root, error) where error is a string if the repo is a monorepo
    with multiple skills and no subdirectory was specified.

    The SKILL.md might be at the root or in a subdirectory.
    Validates that any discovered subdirectory stays within repo_dir to
    prevent symlink-based path traversal (e.g. a subdir symlink pointing outside the tmp clone).
    """
    repo_root = Path(repo_dir).resolve()

    # Check root first
    if os.path.exists(os.path.join(repo_dir, "SKILL.md")):
        return repo_dir, None

    # Check one level deep — collect ALL subdirectories with SKILL.md
    skill_dirs = []
    for entry in sorted(os.listdir(repo_dir)):
        subdir = Path(repo_dir) / entry
        if subdir.is_dir() and os.path.exists(subdir / "SKILL.md"):
            resolved = subdir.resolve()
            if str(resolved).startswith(str(repo_root) + os.sep):
                skill_dirs.append((entry, str(resolved)))

    # Monorepo detected — multiple skills, no subdirectory specified
    if len(skill_dirs) > 1:
        names = [name for name, _ in skill_dirs]
        return None, (
            f"Monorepo detected with {len(skill_dirs)} skills: {', '.join(names)}. "
            f"Pass the URL to a specific skill (e.g. repo/tree/main/{names[0]}) "
            f"instead of the repository root."
        )

    # Single skill found one level deep
    if len(skill_dirs) == 1:
        return skill_dirs[0][1], None

    return repo_dir, None  # Fallback to root even without SKILL.md


def check_skill(url: str):
    """Clone and analyze a skill from a URL.

    Supports monorepo URLs like github.com/user/repo/tree/main/skill-name —
    clones the repo root and navigates to the subdirectory for analysis.
    """
    # Parse monorepo path before normalizing (normalize strips /tree/...)
    _, monorepo_subdir = parse_monorepo_url(url)
    clone_url = normalize_url(url)

    if not validate_url(clone_url):
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

    # Preserve the original URL (with subdir path) for skill_url sent to backend/crucible
    original_url = url.strip().rstrip("/")
    if not original_url.startswith("https://"):
        if re.match(r"^github\.com/", original_url):
            original_url = f"https://{original_url}"
        elif re.match(r"^[a-zA-Z][\w.-]*/[a-zA-Z][\w.-]*", original_url):
            original_url = f"https://github.com/{original_url}"

    # Create temp parent, let git create the subdirectory
    tmp_parent = tempfile.mkdtemp(prefix="skvil-check-")
    tmp_dir = os.path.join(tmp_parent, "repo")

    try:
        # Clone
        if not clone_repo(clone_url, tmp_dir):
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

        # Monorepo: navigate to specific subdirectory if URL contained /tree/branch/path
        if monorepo_subdir:
            target_dir = os.path.join(tmp_dir, monorepo_subdir)
            resolved = Path(target_dir).resolve()
            repo_root = Path(tmp_dir).resolve()
            # Path traversal check
            if not str(resolved).startswith(str(repo_root) + os.sep):
                print(
                    to_json(
                        {
                            "type": "check",
                            "url": url,
                            "error": f"Invalid subdirectory path: {monorepo_subdir}",
                        }
                    )
                )
                return
            if not resolved.is_dir():
                print(
                    to_json(
                        {
                            "type": "check",
                            "url": url,
                            "error": f"Subdirectory not found in repo: {monorepo_subdir}",
                        }
                    )
                )
                return
            skill_root = str(resolved)
        else:
            # Standard flow: find SKILL.md at root or one level deep
            skill_root, monorepo_err = find_skill_root(tmp_dir)
            if monorepo_err:
                print(
                    to_json(
                        {
                            "type": "check",
                            "url": url,
                            "error": monorepo_err,
                        }
                    )
                )
                return

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

        # Check if SKILL.md exists
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
            from lib.formatter import compute_score, risk_level

            result["score"] = compute_score(result["findings"])
            result["risk_level"] = risk_level(result["score"])

        # Submit scan to backend — use original URL (with monorepo subdir) as skill_url
        # so Crucible knows which subdirectory to analyze
        config = load_config()
        reputation = post_scan(result, config, skill_url=original_url)
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
        import traceback

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
