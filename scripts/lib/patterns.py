"""Client-side suspicious pattern detection for skill code."""

import re
import sys

# Binary/compiled file extensions that cannot be pattern-scanned.
# Their mere presence in a skill is suspicious — they may contain arbitrary
# native code or bundle obfuscated packages that bypass all text-based checks.
BINARY_RISK_EXTENSIONS = {
    ".so",  # Linux shared library
    ".dylib",  # macOS shared library
    ".dll",  # Windows shared library
    ".pyd",  # Python extension module (compiled)
    ".whl",  # Python wheel package (ZIP archive)
    ".egg",  # Python egg package (ZIP archive)
}

# Pattern definitions: (category, severity, regex_pattern, description)
PATTERNS = [
    # Network access
    (
        "network",
        "medium",
        r"\b(urllib|requests|httpx|aiohttp|http\.client)\b",
        "Uses HTTP networking library",
    ),
    (
        "network",
        "medium",
        r"\bfrom\s+http\s+import\s+client\b",
        "Uses HTTP networking library (from http import client)",
    ),
    (
        "network",
        "medium",
        r"\b(fetch|XMLHttpRequest|axios)\s*\(",
        "Makes HTTP requests (JS)",
    ),
    (
        "network",
        "low",
        r"=\s*\b(fetch|XMLHttpRequest|axios)\b(?!\s*\()",
        "Assigns fetch/XHR/axios to variable (indirect call evasion)",
    ),
    (
        "network",
        "medium",
        r"(?:subprocess|os\.system|os\.popen)\s*\(.*\b(curl|wget)\b",
        "Executes curl/wget via shell command",
    ),
    (
        "network",
        "high",
        r"(?<!\d\.)(?<!\w)(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.)(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){2}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?!\.\d)(?!\w)",
        "Contains hardcoded IP address",
    ),
    (
        "network",
        "medium",
        r"\bsocket\s*\.\s*(socket|create_connection)\b",
        "Uses raw sockets",
    ),
    (
        "network",
        "high",
        r"169\.254\.169\.254",
        "Accesses cloud metadata endpoint",
    ),
    (
        "network",
        "high",
        r"\b2852039166\b|0x[Aa]9[Ff][Ee][Aa]9[Ff][Ee]\b",
        "Accesses cloud metadata endpoint (integer/hex IP form)",
    ),
    (
        "network",
        "high",
        r"::ffff:(?:a9fe:a9fe|169\.254\.169\.254)",
        "Accesses cloud metadata endpoint (IPv6-mapped form)",
    ),
    # Credential / sensitive file access
    (
        "credentials",
        "high",
        r"~/\.ssh|\.ssh/|id_rsa|id_ed25519|authorized_keys",
        "Accesses SSH keys or config",
    ),
    (
        "credentials",
        "high",
        r"(?:open|read|Path)\s*\(.*\.env\b|(?<!\w)load_dotenv\b",
        "Reads .env file or loads environment secrets",
    ),
    (
        "credentials",
        "high",
        r"credentials\.json|service.account|client_secret",
        "Accesses credential files",
    ),
    (
        "credentials",
        "medium",
        r"(?i)\b(password|passwd|secret|api_key|apikey|token|auth_token)\s*[=:]",
        "Assigns sensitive value (password/secret/token)",
    ),
    (
        "credentials",
        "high",
        r"(?:AKIA[A-Z0-9]{16}|aws_secret_access_key|aws_access_key_id)",
        "Contains AWS credentials or access key pattern",
    ),
    # Shell execution
    (
        "shell",
        "high",
        r"\bsubprocess\.(run|call|Popen|check_output|check_call|getoutput|getstatusoutput)\b",
        "Executes system commands via subprocess",
    ),
    (
        "shell",
        "high",
        r"\bos\.(system|popen|exec[lv]?[pe]?)\s*\(",
        "Executes system commands via os module",
    ),
    (
        "shell",
        "high",
        r"(?<![.\w])\b(exec|eval)\s*\(",
        "Uses exec() or eval() — dynamic code execution",
    ),
    (
        "shell",
        "high",
        r"\bcompile\s*\(.*\bexec\b",
        "Uses compile()+exec() two-step dynamic execution",
    ),
    (
        "shell",
        "critical",
        r"rm\s+-rf\s+[/~]",
        "Destructive rm -rf on root or home directory",
    ),
    (
        "shell",
        "critical",
        r"chmod\s+777",
        "Sets world-writable permissions (chmod 777)",
    ),
    (
        "shell",
        "high",
        r"\b(crontab|systemctl|launchctl)\b",
        "Modifies scheduled tasks or system services",
    ),
    (
        "shell",
        "high",
        r"\bpty\.spawn\s*\(",
        "Spawns pseudo-terminal — interactive shell access",
    ),
    # File access outside skill directory
    (
        "file_access",
        "high",
        r"\.\.(?:/|\\)",
        "Path traversal (../) — accessing parent directories",
    ),
    (
        "file_access",
        "medium",
        r'(?:open|read|write)\s*\(\s*["\']/',
        "Accesses absolute file path",
    ),
    (
        "file_access",
        "high",
        r"~/\.|/home/\w+/\.",
        "Accesses hidden files in home directory",
    ),
    (
        "file_access",
        "high",
        r"\bos\.(symlink|link)\s*\(",
        "Creates symlinks or hardlinks",
    ),
    # Persistence
    (
        "file_access",
        "high",
        r"~/\.(bashrc|bash_profile|profile|zshrc|zprofile)",
        "Writes to shell profile (persistence)",
    ),
    (
        "file_access",
        "high",
        r"/etc/systemd/system/|\.service\b.*\bExecStart\b",
        "Creates or modifies systemd service (persistence)",
    ),
    # Obfuscation
    (
        "obfuscation",
        "medium",
        r"[A-Za-z0-9+/=]{100,}",
        "Contains long base64-encoded string",
    ),
    (
        "obfuscation",
        "high",
        r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){10,}",
        "Contains hex-encoded byte sequence",
    ),
    (
        "obfuscation",
        "medium",
        r"__import__\s*\(",
        "Uses dynamic import (__import__)",
    ),
    (
        "obfuscation",
        "medium",
        r"\bimportlib\.import_module\s*\(",
        "Uses dynamic import (importlib)",
    ),
    (
        "obfuscation",
        "high",
        r"\bzlib\.decompress\b.*\bexec\b|\bexec\b.*\bzlib\.decompress\b",
        "Decompresses and executes payload",
    ),
    (
        "obfuscation",
        "high",
        r"\bexec\s*\(.*\bb64decode\b|\bb64decode\b.*\bexec\s*\(",
        "Decodes base64 and executes payload",
    ),
    (
        "obfuscation",
        "medium",
        r"\bcodecs\.decode\s*\(.*['\"]rot",
        "Uses ROT13/codec-based obfuscation",
    ),
    # Deserialization — arbitrary code execution
    (
        "deserialization",
        "critical",
        r"\b(pickle|cPickle|marshal)\.(loads?|load)\s*\(",
        "Deserializes data — can execute arbitrary code",
    ),
    (
        "deserialization",
        "high",
        r"\byaml\.(?:unsafe_)?load\s*\(",
        "Unsafe YAML deserialization",
    ),
    # Native code / FFI
    (
        "native_code",
        "high",
        r"\b(ctypes|cffi|ctypes\.cdll)\b",
        "Loads native libraries — arbitrary memory access",
    ),
    # Reverse shell patterns
    (
        "reverse_shell",
        "critical",
        r"/dev/tcp/|/dev/udp/",
        "Reverse shell via /dev/tcp",
    ),
    (
        "reverse_shell",
        "critical",
        r"\bnc\s+.*-e\s|ncat\s+.*-e\s",
        "Reverse shell via netcat",
    ),
    (
        "reverse_shell",
        "critical",
        r"bash\s+-i\s+>&\s*/dev/tcp",
        "Bash reverse shell",
    ),
    # Prompt injection (in SKILL.md or code)
    (
        "prompt_injection",
        "critical",
        r"(?i)(ignore\s+(previous|prior|above)\s+(instructions?|prompts?))",
        "Prompt injection: ignore previous instructions",
    ),
    (
        "prompt_injection",
        "critical",
        r"(?i)(disregard\s+(all|any|previous)\s+(instructions?|rules?))",
        "Prompt injection: disregard instructions",
    ),
    (
        "prompt_injection",
        "critical",
        r"(?i)(new\s+instructions?|you\s+are\s+now(?!\s+(?:entering|leaving|exiting|connected|disconnected|logged|ready|on\s+(?:the|a|this|your)\b))|from\s+now\s+on\s+you)",
        "Prompt injection: overriding agent behavior",
    ),
    (
        "prompt_injection",
        "high",
        r"(?i)(do\s+not\s+reveal|never\s+mention|hide\s+this\s+from)",
        "Prompt injection: hiding behavior from user",
    ),
    # Multilingual prompt injection — PT-BR, ES, FR, DE
    # "ignore (as) instruções" / "ignora instrucciones" / "ignorez instructions" / "ignoriere Anweisungen"
    (
        "prompt_injection",
        "critical",
        r"(?i)(ignore?\s+(as\s+)?instru[cç][oõ]es|ignora[r]?\s+(las\s+)?instrucciones|ignore[zr]?\s+(les\s+)?instructions\b|ignoriere\s+(die\s+)?(vorherigen\s+)?anweisungen)",
        "Prompt injection: ignore instructions (PT/ES/FR/DE)",
    ),
    # "a partir de agora/ahora/maintenant" / "ab jetzt" / "novas/nuevas/nouvelles/neue instruções"
    # "você é agora" / "tu eres ahora" / "vous êtes maintenant" / "du bist jetzt"
    (
        "prompt_injection",
        "critical",
        r"(?i)(a\s+partir\s+de\s+agora|a\s+partir\s+de\s+ahora|[aà]\s+partir\s+de\s+maintenant|ab\s+jetzt|novas?\s+instru[cç][oõ]es|nuevas\s+instrucciones|nouvelles\s+instructions|neue\s+anweisungen|voc[eê]\s+[eé]\s+agora|(?:tu|usted)\s+eres\s+ahora|vous\s+[eê]tes\s+maintenant|du\s+bist\s+jetzt)",
        "Prompt injection: new instructions / identity override (PT/ES/FR/DE)",
    ),
    # "não revele" / "no reveles" / "ne révèle pas" / "enthülle nicht" / "nunca mencione" / "ne mentionnez jamais"
    (
        "prompt_injection",
        "high",
        r"(?i)(n[aã]o\s+revel[ea]|no\s+reveles|ne\s+r[eé]v[eè]le[z]?\s+pas|enth[uü]lle\s+(das\s+)?nicht|nunca\s+mencione[s]?|ne\s+mentionnez?\s+jamais)",
        "Prompt injection: hide behavior (PT/ES/FR/DE)",
    ),
    # Environment manipulation
    (
        "environment",
        "high",
        r"\bos\.environ\s*\[.*\]\s*=",
        "Modifies environment variables",
    ),
    (
        "environment",
        "low",
        r"\bos\.environ\.get\s*\(|\bos\.getenv\s*\(",
        "Reads environment variables (may exfiltrate secrets)",
    ),
    (
        "environment",
        "high",
        r"\bwebbrowser\.open\s*\(",
        "Opens URLs in the browser",
    ),
    (
        "environment",
        "high",
        r"\bsys\.path\.(insert|append)\s*\(",
        "Manipulates Python import path (potential hijacking)",
    ),
]

# Sliding window size for multi-line pattern detection.
# scan_content() joins N consecutive lines with a space and runs all patterns
# against each window, catching constructs split across lines to evade per-line scanning.
# Example: cmd = "nc "; cmd += "-e /bin/sh host 4444"; os.system(cmd)
MULTILINE_WINDOW_SIZE = 3

# Compiled patterns (lazy init)
_compiled = None


def _compile_patterns():
    global _compiled
    if _compiled is None:
        _compiled = []
        for category, severity, pattern, description in PATTERNS:
            try:
                compiled = re.compile(pattern)
                _compiled.append((category, severity, compiled, description))
            except re.error as e:
                print(f"Warning: failed to compile pattern '{pattern}': {e}", file=sys.stderr)
                continue
    return _compiled


def scan_content(content: str, file_path: str) -> list:
    """Scan a single file's content for suspicious patterns.

    Uses two passes:
    1. Per-line: standard line-by-line pattern matching.
    2. Sliding window: N consecutive lines joined with a space, catching constructs
       split across lines (e.g. reverse shell built via string concatenation).

    Deduplication by (category, description, file) is handled by scan_skill().

    Returns list of findings:
    [{"severity", "category", "description", "file", "line"}, ...]
    """
    findings = []
    patterns = _compile_patterns()

    lines = content.split("\n")

    # Pass 1 — per-line scan
    for line_num, line in enumerate(lines, start=1):
        for category, severity, compiled, description in patterns:
            if compiled.search(line):
                findings.append(
                    {
                        "severity": severity,
                        "category": category,
                        "description": description,
                        "file": file_path,
                        "line": line_num,
                    }
                )

    # Pass 2 — sliding window (catches multi-line evasion)
    for start in range(len(lines) - MULTILINE_WINDOW_SIZE + 1):
        window = " ".join(lines[start : start + MULTILINE_WINDOW_SIZE])
        line_num = start + 1  # report first line of the window
        for category, severity, compiled, description in patterns:
            if compiled.search(window):
                findings.append(
                    {
                        "severity": severity,
                        "category": category,
                        "description": description,
                        "file": file_path,
                        "line": line_num,
                    }
                )

    return findings


def scan_skill(code_snippets: dict) -> list:
    """Scan all code snippets of a skill for suspicious patterns.

    Args:
        code_snippets: dict mapping relative file paths to file contents

    Returns list of all findings across all files, deduplicated by
    (category, description, file) to avoid noise from repeated patterns.
    """
    all_findings = []
    seen = set()

    for file_path, content in code_snippets.items():
        file_findings = scan_content(content, file_path)
        for finding in file_findings:
            key = (finding["category"], finding["description"], finding["file"])
            if key not in seen:
                seen.add(key)
                all_findings.append(finding)

    return all_findings


def scan_binary_presence(files: list) -> list:
    """Emit findings for compiled binary or package archive files.

    Binary files cannot be scanned for patterns — their content is opaque.
    Presence alone is a high-severity signal: a skill shipping .so/.dll/.whl
    can execute arbitrary native code or bundle obfuscated Python packages
    that bypass all text-based pattern detection.

    Args:
        files: list of relative file paths from collect_skill() (may include
               '[symlink — skipped]' annotations which are ignored)
    """
    findings = []
    for file_path in files:
        if file_path.endswith(" [symlink — skipped]"):
            continue
        lower = file_path.lower()
        for ext in BINARY_RISK_EXTENSIONS:
            if lower.endswith(ext):
                findings.append(
                    {
                        "severity": "high",
                        "category": "native_code",
                        "description": (
                            f"Skill ships a compiled binary or package archive ({ext})"
                            " — content cannot be pattern-scanned"
                        ),
                        "file": file_path,
                        "line": 0,
                    }
                )
                break  # one finding per file
    return findings


def scan_oversized_files(oversized_code_files: list) -> list:
    """Emit findings for code files that exceeded the 50KB scan limit.

    Files above MAX_FILE_SIZE are hashed but not pattern-scanned.
    An attacker can pad a file past the threshold and hide a payload beyond
    the read boundary — the content is invisible to all text-based checks.

    Args:
        oversized_code_files: list of relative file paths from collect_skill()
                              that are code files exceeding MAX_FILE_SIZE
    """
    findings = []
    for file_path in oversized_code_files:
        findings.append(
            {
                "severity": "medium",
                "category": "obfuscation",
                "description": (
                    "Code file exceeds 50KB scan limit — content beyond threshold"
                    " is not pattern-scanned (possible padding attack)"
                ),
                "file": file_path,
                "line": 0,
            }
        )
    return findings
