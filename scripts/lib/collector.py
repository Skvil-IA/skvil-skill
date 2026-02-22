"""Collect metadata and code from skill directories."""

import os
import re
from pathlib import Path

# Max file size to read (50KB)
MAX_FILE_SIZE = 50 * 1024

# Tail scan size for oversized files — read the last 10KB in addition to the first 50KB.
# Catches payloads appended after a padding prefix designed to push the malicious
# code beyond the MAX_FILE_SIZE boundary (SCANNER-03 fix).
TAIL_SCAN_SIZE = 10 * 1024

# Max files per skill to prevent CPU DoS
MAX_FILE_COUNT = 1000

# File extensions to analyze for suspicious patterns
CODE_EXTENSIONS = {
    ".py",
    ".pyx",  # Cython — Python-like syntax compiled to C
    ".pxd",  # Cython declaration files
    ".js",
    ".ts",
    ".sh",
    ".bash",
    ".zsh",
    ".rb",
    ".go",
    ".rs",
    ".lua",
    ".pl",
    ".php",
    ".md",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".cfg",  # Python/tool configs (setup.cfg, pytest.ini-style)
    ".conf",  # General config files
    ".ini",  # INI-format configs
}


def parse_frontmatter(content: str) -> dict:
    """Parse YAML frontmatter from a SKILL.md file.

    Minimal parser — splits on '---' delimiters, extracts key-value pairs.
    Handles simple strings and multiline strings (>- syntax).
    No PyYAML dependency.
    """
    frontmatter = {}
    match = re.match(r"^---\s*\n(.*?)\n---", content, re.DOTALL)
    if not match:
        return frontmatter

    block = match.group(1)
    current_key = None
    current_value = []

    for line in block.split("\n"):
        # Key-value on same line: 'key: value' or 'key: >-'
        kv_match = re.match(r"^(\w[\w-]*)\s*:\s*(.*)", line)
        if kv_match:
            # Save previous key if exists
            if current_key is not None:
                frontmatter[current_key] = _finalize_value(current_value)
            current_key = kv_match.group(1)
            value = kv_match.group(2).strip()
            current_value = [] if value in (">-", ">", "|", "|-") else [value.strip('"').strip("'")]
        elif current_key is not None and line.startswith("  "):
            # Continuation line for multiline value
            current_value.append(line.strip())

    if current_key is not None:
        frontmatter[current_key] = _finalize_value(current_value)

    return frontmatter


def _finalize_value(parts: list) -> str:
    """Join multiline value parts into a single string."""
    return " ".join(parts).strip()


def get_body(content: str) -> str:
    """Extract the markdown body (after frontmatter) from SKILL.md."""
    match = re.match(r"^---\s*\n.*?\n---\s*\n(.*)", content, re.DOTALL)
    if match:
        return match.group(1).strip()
    return content.strip()


def collect_skill(skill_dir: str) -> dict:
    """Collect all metadata and code from a skill directory.

    Returns a dict with:
      - name: skill name (from frontmatter or directory name)
      - path: absolute path to skill directory
      - frontmatter: parsed YAML frontmatter dict
      - body: markdown body of SKILL.md
      - files: list of relative file paths
      - code_snippets: dict mapping relative paths to file contents (up to MAX_FILE_SIZE)
      - oversized_code_files: list of relative paths for code files exceeding MAX_FILE_SIZE
    """
    skill_path = Path(skill_dir).resolve()
    result = {
        "name": skill_path.name,
        "path": str(skill_path),
        "frontmatter": {},
        "body": "",
        "files": [],
        "code_snippets": {},
        "oversized_code_files": [],
    }

    # Read SKILL.md
    skill_md = skill_path / "SKILL.md"
    if skill_md.exists():
        try:
            content = skill_md.read_text(encoding="utf-8", errors="replace")
            result["frontmatter"] = parse_frontmatter(content)
            result["body"] = get_body(content)
            if "name" in result["frontmatter"]:
                # Sanitize: truncate and strip control chars
                name = result["frontmatter"]["name"][:100]
                name = re.sub(r"[\x00-\x1f]", "", name)
                result["name"] = name
        except (PermissionError, OSError):
            pass

    # Enumerate files and collect code
    skip_dirs = {".git", "__pycache__", "node_modules", ".venv", "venv"}
    file_count = 0
    for dirpath, dirnames, filenames in os.walk(str(skill_path)):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for filename in sorted(filenames):
            if file_count >= MAX_FILE_COUNT:
                break
            filepath = Path(dirpath) / filename

            # Skip ALL symlinks — consistent with hasher.py
            if filepath.is_symlink():
                rel = str(filepath.relative_to(skill_path))
                result["files"].append(f"{rel} [symlink — skipped]")
                continue

            rel_path = str(filepath.relative_to(skill_path))
            result["files"].append(rel_path)
            file_count += 1

            # Read code files within size limit
            ext = filepath.suffix.lower()
            if ext in CODE_EXTENSIONS:
                try:
                    size = filepath.lstat().st_size
                    if size <= MAX_FILE_SIZE:
                        code = filepath.read_text(encoding="utf-8", errors="replace")
                        result["code_snippets"][rel_path] = code
                    else:
                        # File exceeds scan limit — record for oversized finding.
                        # Also scan the first MAX_FILE_SIZE bytes + last TAIL_SCAN_SIZE bytes
                        # to catch payloads appended after a padding prefix (SCANNER-03).
                        result["oversized_code_files"].append(rel_path)
                        try:
                            with filepath.open("rb") as fh:
                                head = fh.read(MAX_FILE_SIZE).decode("utf-8", errors="replace")
                                fh.seek(max(0, size - TAIL_SCAN_SIZE))
                                tail = fh.read(TAIL_SCAN_SIZE).decode("utf-8", errors="replace")
                            result["code_snippets"][rel_path] = head + "\n" + tail
                        except (PermissionError, OSError):
                            pass
                except (PermissionError, OSError):
                    continue

    return result


def discover_skills(extra_dirs: list = None) -> list:
    """Discover all installed skill directories.

    Checks:
      - ~/.openclaw/skills/   (source: "global")
      - ./skills/ (current workspace, source: "local")
      - Any extra directories provided (source: "extra")

    Returns list of dicts: [{"path": str, "source": str}, ...]

    The "source" field distinguishes globally-installed skills from workspace-local
    ones. Local skills (./skills/) come from the current working directory and may
    be unvetted — callers should surface a warning to the user.
    """
    # Tagged search dirs: (path, source_label)
    tagged_dirs = []

    # Default OpenClaw skills directory — trusted, user-installed
    home_skills = Path.home() / ".openclaw" / "skills"
    if home_skills.exists():
        tagged_dirs.append((home_skills, "global"))

    # Current workspace skills — CWD-relative, potentially untrusted
    workspace_skills = Path.cwd() / "skills"
    if workspace_skills.exists():
        tagged_dirs.append((workspace_skills, "local"))

    # Extra directories
    if extra_dirs:
        for d in extra_dirs:
            p = Path(d).expanduser().resolve()
            if p.exists():
                tagged_dirs.append((p, "extra"))

    skills = []
    seen = set()
    for search_dir, source in tagged_dirs:
        if not search_dir.is_dir():
            continue
        resolved_search = str(search_dir.resolve())
        for entry in sorted(search_dir.iterdir()):
            if not entry.is_dir():
                continue
            resolved = str(entry.resolve())
            # Containment check: resolved path must be inside search_dir
            if not resolved.startswith(resolved_search + os.sep):
                continue

            if (entry / "SKILL.md").exists():
                # Standard case: SKILL.md at root of skill directory
                if resolved not in seen:
                    seen.add(resolved)
                    skills.append({"path": resolved, "source": source})
            else:
                # Monorepo case: agent installed a full repo, SKILL.md lives in
                # subdirectories.  Each subdirectory with its own SKILL.md is
                # treated as a separate skill.
                for subentry in sorted(entry.iterdir()):
                    if subentry.is_dir() and (subentry / "SKILL.md").exists():
                        sub_resolved = str(subentry.resolve())
                        if sub_resolved.startswith(resolved + os.sep) and sub_resolved not in seen:
                            seen.add(sub_resolved)
                            skills.append({"path": sub_resolved, "source": source})

    return skills
