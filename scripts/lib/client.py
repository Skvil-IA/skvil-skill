"""HTTP client for skvil-kedavra backend API — stdlib only (urllib.request)."""

import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_API_URL = "https://api.skvil.com"
TIMEOUT = 10  # seconds
MAX_RESPONSE_SIZE = 1024 * 1024  # 1MB


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Disable automatic redirect following to prevent SSRF."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _build_ssl_context() -> ssl.SSLContext:
    """Create a hardened TLS context for API requests.

    Explicitly enforces certificate verification and hostname checking so the
    security posture is never accidentally weakened by a future code change or
    environment variable (e.g. PYTHONHTTPSVERIFY=0 does not affect this context).

    Full certificate pinning (HPKP-style) is intentionally omitted:
    - The client uses stdlib only — DER cert parsing requires the `cryptography`
      package, which would break the zero-deps constraint.
    - skvil.com sits behind Cloudflare; the cert the client sees is a Cloudflare
      edge cert that rotates automatically, making a stable pin impractical.
    - Standard TLS with the system CA bundle is the correct security boundary here.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


# Build an opener that does NOT follow redirects and uses a hardened TLS context
_opener = urllib.request.build_opener(
    _NoRedirectHandler,
    urllib.request.HTTPSHandler(context=_build_ssl_context()),
)


def load_config():
    """Load API key and URL from env vars or ~/.skvil/config.

    api_key: read from SKVIL_KEDAVRA_API_KEY env var, then ~/.skvil/config.
    api_url: read from SKVIL_KEDAVRA_API_URL env var ONLY — never from config file.

    Restricting api_url to env vars prevents config poisoning: a malicious skill
    with file-write capability could redirect all scans to an attacker-controlled
    server by writing api_url=https://attacker.com to ~/.skvil/config.
    An env var override requires explicit shell access, a higher attack bar, and
    is scoped to the current process — not persisted across invocations.
    """
    api_key = os.environ.get("SKVIL_KEDAVRA_API_KEY")
    api_url = os.environ.get("SKVIL_KEDAVRA_API_URL")

    # Config file: api_key only — api_url intentionally not supported here
    config_path = Path.home() / ".skvil" / "config"
    if config_path.exists():
        try:
            for line in config_path.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, v = line.split("=", 1)
                    k, v = k.strip(), v.strip()
                    if k == "api_key" and not api_key:
                        api_key = v
        except OSError:
            pass

    resolved_url = (api_url or DEFAULT_API_URL).rstrip("/")

    # Reject non-HTTPS URLs unless explicitly pointing to localhost (local dev).
    # Falls back to DEFAULT_API_URL rather than sending the API key in plaintext.
    is_localhost = any(h in resolved_url for h in ("localhost", "127.0.0.1", "::1"))
    if not resolved_url.startswith("https://") and not is_localhost:
        print(
            f"[skvil] WARNING: SKVIL_KEDAVRA_API_URL '{resolved_url}' is not HTTPS — "
            "falling back to api.skvil.com to protect your API key.",
            file=sys.stderr,
        )
        resolved_url = DEFAULT_API_URL

    return {
        "api_key": api_key,
        "api_url": resolved_url,
    }


def _request(method, url, api_key, data=None):
    """Make an HTTP request, return parsed JSON or None on failure."""
    headers = {"Content-Type": "application/json", "User-Agent": "skvil/0.3.0"}
    if api_key:
        headers["X-API-Key"] = api_key

    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    try:
        with _opener.open(req, timeout=TIMEOUT) as resp:
            raw = resp.read(MAX_RESPONSE_SIZE + 1)
            if len(raw) > MAX_RESPONSE_SIZE:
                print("[skvil] API response too large — ignoring", file=sys.stderr)
                return None
            return json.loads(raw.decode())
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = json.loads(e.read(4096).decode()).get("detail", "")
        except Exception:
            pass
        print(
            f"[skvil] API error {e.code}: {detail or e.reason}",
            file=sys.stderr,
        )
        return None
    except (urllib.error.URLError, OSError, TimeoutError):
        print("[skvil] Backend unreachable — falling back to local mode", file=sys.stderr)
        return None


def auto_register(config=None):
    """Register with the backend and get a free API key. Saves to ~/.skvil/config."""
    if config is None:
        config = load_config()

    url = f"{config['api_url']}/register"
    result = _request("POST", url, None)
    if not result or "api_key" not in result:
        return None

    api_key = result["api_key"]
    config_dir = Path.home() / ".skvil"
    config_path = config_dir / "config"
    try:
        config_dir.mkdir(parents=True, exist_ok=True)
        existing = config_path.read_text() if config_path.exists() else ""
        key_prefix = "api_key"
        if f"{key_prefix}=" not in existing:
            with config_path.open("a") as f:
                f.write(f"{key_prefix}={api_key}\n")
        print(f"[skvil] registered — key saved to {config_path}", file=sys.stderr)
    except OSError:
        pass

    return api_key


def post_scan(result, config=None, skill_url=None):
    """POST scan result to /scan. Returns reputation data or None."""
    if config is None:
        config = load_config()

    if not config["api_key"]:
        # No key found — try auto-registration
        new_key = auto_register(config)
        if new_key:
            config["api_key"] = new_key
        else:
            return None

    payload = {
        "name": result["name"],
        "composite_hash": result["composite_hash"],
        "file_count": result["file_count"],
        "file_hashes": result["file_hashes"],
        "score": result["score"],
        "risk_level": result["risk_level"],
        "findings": result["findings"],
        "frontmatter": result.get("frontmatter", {}),
    }
    if skill_url:
        payload["skill_url"] = skill_url
    url = f"{config['api_url']}/scan"
    return _request("POST", url, config["api_key"], payload)


def get_verify(composite_hash, config=None):
    """GET /verify/{hash}. Returns verification data or None."""
    if config is None:
        config = load_config()

    url = f"{config['api_url']}/verify/{composite_hash}"
    return _request("GET", url, config.get("api_key"))


def merge_reputation(result, reputation):
    """Merge backend reputation data into a local scan result."""
    if not reputation:
        return
    result["reputation"] = {
        "score": reputation.get("reputation_score"),
        "total_scans": reputation.get("total_scans"),
        "certification": reputation.get("certification"),
    }


def merge_verify(result, verification):
    """Merge backend verification data into a local verify result."""
    if not verification or not verification.get("known"):
        return
    result["reputation"] = {
        "score": verification.get("reputation_score"),
        "total_scans": verification.get("total_scans"),
        "certification": verification.get("certification"),
        "risk_summary": verification.get("risk_summary"),
    }
