"""Format scan and check results as structured JSON output."""

import json
from collections import Counter
from datetime import datetime, timezone

# Score deductions per severity
SEVERITY_DEDUCTIONS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
}

# Category accumulation: when a category has >= this many findings,
# apply an extra penalty to prevent many low-severity findings from
# composing into a false "safe" verdict (C1 fix).
CATEGORY_ACCUMULATION_THRESHOLD = 3
CATEGORY_ACCUMULATION_PENALTY = 10


def compute_score(findings: list, file_count: int = -1) -> int:
    """Compute a safety score (0-100) based on findings.

    Starts at 100 and deducts points per finding based on severity.
    Applies category accumulation penalty: 3+ findings in the same category
    incur an extra deduction, preventing many individually-low findings
    from staying in the "safe" zone (C1 fix).
    If file_count is 0 (no code to analyze), caps score at 70.
    Client-side scoring only — backend may adjust with reputation data.
    """
    score = 100
    for finding in findings:
        severity = finding.get("severity", "low")
        score -= SEVERITY_DEDUCTIONS.get(severity, 3)

    # Category accumulation penalty (C1 fix): many findings in the same
    # category signal compound risk even if each is individually low.
    category_counts = Counter(f.get("category", "") for f in findings)
    for count in category_counts.values():
        if count >= CATEGORY_ACCUMULATION_THRESHOLD:
            score -= CATEGORY_ACCUMULATION_PENALTY

    score = max(0, min(100, score))
    # Empty skill with no code shouldn't get a perfect score
    if file_count == 0:
        score = min(score, 70)
    return score


def risk_level(score: int) -> str:
    """Map score to risk level."""
    if score >= 80:
        return "safe"
    elif score >= 50:
        return "caution"
    else:
        return "danger"


def format_skill_result(
    name: str, path: str, composite_hash: str, file_hashes: dict, findings: list, frontmatter: dict
) -> dict:
    """Format analysis result for a single skill."""
    fcount = len(file_hashes)
    score = compute_score(findings, file_count=fcount)
    return {
        "name": name,
        "path": path,
        "composite_hash": f"sha256:{composite_hash}",
        "file_count": fcount,
        "file_hashes": file_hashes,
        "score": score,
        "risk_level": risk_level(score),
        "findings": findings,
        "frontmatter": frontmatter,
    }


def format_scan_output(results: list) -> dict:
    """Format the full scan output with summary."""
    summary = {"safe": 0, "caution": 0, "danger": 0}
    for r in results:
        level = r.get("risk_level", "safe")
        if level in summary:
            summary[level] += 1

    return {
        "type": "scan",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "skills_scanned": len(results),
        "results": results,
        "summary": summary,
        "mode": "local",
    }


def format_check_output(url: str, result: dict) -> dict:
    """Format the pre-install check output.

    Includes a `post_install_verify` block with the expected composite_hash
    so the agent can detect TOCTOU tampering: if the hash of the installed
    skill differs from the hash that was checked, the repo was modified
    between analysis and install.
    """
    skill_name = result.get("name", "")
    composite_hash = result.get("composite_hash", "")
    return {
        "type": "check",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "url": url,
        "result": result,
        "mode": "local",
        "post_install_verify": {
            "skill_name": skill_name,
            "expected_hash": composite_hash,
            "instruction": (
                f"After installing '{skill_name}', immediately run "
                f"`skvil verify {skill_name}` and confirm the composite_hash "
                f"matches '{composite_hash}'. "
                "A mismatch means the skill was modified after this analysis — "
                "uninstall immediately and alert the user."
            ),
        },
    }


def to_json(data: dict) -> str:
    """Serialize to JSON string."""
    return json.dumps(data, indent=2, ensure_ascii=False)
