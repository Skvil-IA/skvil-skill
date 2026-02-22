#!/usr/bin/env python3
"""Skvil Verify — Verify a specific installed skill's hash and analyze it."""

import os
import sys

# Add parent directory to path so lib can be imported
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from datetime import datetime, timedelta, timezone
from pathlib import Path

from lib.client import get_verify, load_config, merge_reputation, merge_verify, post_scan
from lib.collector import collect_skill
from lib.formatter import format_skill_result, to_json
from lib.hasher import composite_hash, hash_directory, skvil_kedavra_self_hash
from lib.patterns import scan_binary_presence, scan_oversized_files, scan_skill
from lib.updater import auto_update

_SKVIL_KEDAVRA_DIR = str(Path(os.path.abspath(__file__)).parent.parent.resolve())


def find_skill(name: str) -> str:
    """Find a skill directory by name.

    Validates that the resolved path stays within a skills directory
    to prevent path traversal attacks.

    Handles monorepo installs: if the directory has no root SKILL.md,
    looks one level deep for a subdirectory matching the skill name
    (or any single subdirectory with SKILL.md).
    """
    search_dirs = [
        Path.home() / ".openclaw" / "skills",
        Path.cwd() / "skills",
    ]

    for search_dir in search_dirs:
        if not search_dir.exists():
            continue
        skill_dir = search_dir / name
        if not (skill_dir.exists() and skill_dir.is_dir()):
            continue
        resolved = skill_dir.resolve()
        # Ensure resolved path is still under the search directory
        if not str(resolved).startswith(str(search_dir.resolve()) + os.sep):
            continue

        # Standard case: SKILL.md at root
        if (resolved / "SKILL.md").exists():
            return str(resolved)

        # Monorepo case: look for subdirectory with SKILL.md
        # Prefer subdirectory matching the skill name
        skill_subdirs = []
        for subentry in sorted(resolved.iterdir()):
            if subentry.is_dir() and (subentry / "SKILL.md").exists():
                sub_resolved = subentry.resolve()
                if str(sub_resolved).startswith(str(resolved) + os.sep):
                    if subentry.name == name:
                        return str(sub_resolved)
                    skill_subdirs.append(str(sub_resolved))

        # No exact name match — return first subdirectory with SKILL.md
        if skill_subdirs:
            return skill_subdirs[0]

    return None


def verify_skill(name: str):
    """Compute hash and analyze a specific installed skill.

    In local mode, computes the hash and runs pattern detection.
    With backend (future), verifies hash against the registry.
    """
    skill_dir = find_skill(name)

    if not skill_dir:
        print(
            to_json(
                {
                    "type": "verify",
                    "skill_name": name,
                    "error": f"Skill '{name}' not found in ~/.openclaw/skills/ or ./skills/",
                }
            )
        )
        return

    # Collect and analyze
    skill_data = collect_skill(skill_dir)
    file_hashes = hash_directory(skill_dir)
    comp_hash = composite_hash(file_hashes)
    findings = (
        scan_skill(skill_data["code_snippets"])
        + scan_binary_presence(skill_data["files"])
        + scan_oversized_files(skill_data["oversized_code_files"])
    )

    result = format_skill_result(
        name=skill_data["name"],
        path=skill_data["path"],
        composite_hash=comp_hash,
        file_hashes=file_hashes,
        findings=findings,
        frontmatter=skill_data["frontmatter"],
    )

    # Submit scan to backend (auto-registers if needed), fall back to public verify
    config = load_config()
    mode = "local"
    skill_url = skill_data["frontmatter"].get("skill_url")
    reputation = post_scan(result, config, skill_url=skill_url)
    if reputation:
        merge_reputation(result, reputation)
        mode = "connected"
    else:
        verification = get_verify(result["composite_hash"], config)
        if verification:
            merge_verify(result, verification)
            mode = "connected"

    now = datetime.now(timezone.utc)
    next_check = (now + timedelta(days=7)).strftime("%Y-%m-%d")

    output = {
        "type": "verify",
        "timestamp": now.isoformat(),
        "result": result,
        "mode": mode,
        # Self-integrity tag: allows the agent to detect if skvil-kedavra itself was replaced.
        # Compare against the trusted hash from a prior `skvil-kedavra verify skvil-kedavra` run.
        "skvil_kedavra_hash": skvil_kedavra_self_hash(_SKVIL_KEDAVRA_DIR),
        # Post-install monitoring hint: skills can self-modify after the initial scan.
        # The agent should re-run skvil-kedavra verify periodically to detect tampering.
        "next_check": next_check,
        "monitor_instruction": (
            f"Re-run `skvil verify {name}` by {next_check} to detect any "
            "post-install modifications. If the composite_hash has changed "
            "since this run, the skill was tampered with — remove it immediately."
        ),
    }

    if mode == "local":
        output["note"] = "Backend unreachable — running in local mode. Results are based on local analysis only."

    print(to_json(output))


def main():
    auto_update(_SKVIL_KEDAVRA_DIR)

    if len(sys.argv) < 2:
        print(
            to_json(
                {
                    "type": "verify",
                    "error": "Usage: skvil_kedavra_verify.py <skill-name>",
                }
            )
        )
        sys.exit(1)

    name = sys.argv[1]
    verify_skill(name)


if __name__ == "__main__":
    main()
