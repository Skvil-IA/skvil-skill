#!/usr/bin/env python3
"""Skvil Scan — Scan all installed skills for security issues."""

import os
import sys
from pathlib import Path

# Add parent directory to path so lib can be imported
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib.client import load_config, merge_reputation, post_scan
from lib.collector import collect_skill, discover_skills
from lib.formatter import format_scan_output, format_skill_result, to_json
from lib.hasher import composite_hash, hash_directory, skvil_kedavra_self_hash
from lib.patterns import scan_binary_presence, scan_oversized_files, scan_skill

# Resolve the actual installation directory of the running skvil-kedavra instance.
# Used to exclude ourselves by resolved path — NOT by directory name.
# Name-based exclusion is bypassable: a malicious skill installed as "skvil-kedavra"
# would be silently excluded, effectively replacing the scanner undetected.
_SELF_DIR = str(Path(os.path.abspath(__file__)).parent.parent.resolve())
SELF_NAME = "skvil"  # kept only for squatter detection


def scan_all():
    """Discover and scan all installed skills (excludes skvil-kedavra itself by path)."""
    all_entries = discover_skills()

    # Exclude by resolved path, not by name
    skill_entries = [e for e in all_entries if str(Path(e["path"]).resolve()) != _SELF_DIR]

    # Detect squatters: skills named "skvil-kedavra" that are NOT this running instance.
    # These are included in the scan (not excluded) and trigger a security alert.
    squatters = [e["path"] for e in skill_entries if os.path.basename(e["path"]) == SELF_NAME]

    # Local skills come from ./skills/ (CWD-relative) — not from the trusted global dir.
    local_skills = [e["path"] for e in skill_entries if e["source"] == "local"]

    if not skill_entries:
        output = {
            "type": "scan",
            "skills_scanned": 0,
            "results": [],
            "summary": {"safe": 0, "caution": 0, "danger": 0},
            "message": "No skills found. Checked ~/.openclaw/skills/ and ./skills/",
            "mode": "local",
            "skvil_kedavra_hash": skvil_kedavra_self_hash(_SELF_DIR),
        }
        print(to_json(output))
        return

    config = load_config()
    mode = "connected" if config["api_key"] else "local"

    results = []
    for entry in skill_entries:
        skill_dir = entry["path"]
        source = entry["source"]
        try:
            # Collect metadata and code
            skill_data = collect_skill(skill_dir)

            # Compute hashes
            file_hashes = hash_directory(skill_dir)
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
                path=skill_data["path"],
                composite_hash=comp_hash,
                file_hashes=file_hashes,
                findings=findings,
                frontmatter=skill_data["frontmatter"],
            )

            # Tag skill origin so the agent/user can distinguish global vs local
            result["source"] = source

            # Submit to backend and merge reputation
            skill_url = skill_data["frontmatter"].get("skill_url")
            reputation = post_scan(result, config, skill_url=skill_url)
            if reputation:
                merge_reputation(result, reputation)
            elif config["api_key"]:
                mode = "local"  # backend unreachable

            results.append(result)

        except Exception as e:
            import traceback

            traceback.print_exc(file=sys.stderr)
            results.append(
                {
                    "name": os.path.basename(skill_dir),
                    "path": skill_dir,
                    "source": source,
                    "score": 0,
                    "risk_level": "danger",
                    "error": str(e),
                    "findings": [],
                }
            )

    output = format_scan_output(results)
    output["mode"] = mode
    output["skvil_kedavra_hash"] = skvil_kedavra_self_hash(_SELF_DIR)
    output["monitor_note"] = (
        "Skills can self-modify after the initial scan. "
        "Re-run skvil scan periodically (or use `skvil verify <name>` per skill) "
        "to detect post-install tampering."
    )

    if local_skills:
        output["local_skills_note"] = (
            f"{len(local_skills)} skill(s) found in ./skills/ (current working directory). "
            "Local skills are not in your global ~/.openclaw/skills/ directory — "
            "their presence here depends on where you ran skvil from. "
            "Treat them as unvetted if the working directory is not fully trusted. "
            f"Path(s): {local_skills}"
        )

    if squatters:
        output["security_alert"] = (
            f"SCANNER REPLACEMENT ATTACK DETECTED: {len(squatters)} skill(s) named "
            f"'{SELF_NAME}' found outside this skvil-kedavra installation. "
            f"A malicious skill may be attempting to impersonate or replace the scanner. "
            f"Verify your skvil installation immediately. "
            f"Suspicious path(s): {squatters}"
        )

    print(to_json(output))


if __name__ == "__main__":
    scan_all()
