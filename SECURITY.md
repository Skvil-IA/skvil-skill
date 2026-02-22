# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.3.x   | ✅        |
| < 0.3   | ❌        |

## Reporting a Vulnerability

**Please do not open public GitHub issues for security vulnerabilities.**

Report security issues via email: **security@skvil.com**

Include in your report:
- Description of the vulnerability and its impact
- Steps to reproduce (proof-of-concept if applicable)
- Suggested fix, if any

### Response Timeline

| Stage | Target |
|-------|--------|
| Acknowledgement | 48 hours |
| Initial assessment | 7 days |
| Fix or mitigation | 30 days |
| Public disclosure | After fix is deployed |

We will keep you informed at each stage. If you do not receive an acknowledgement
within 48 hours, follow up via GitHub (open a blank issue mentioning you sent a
security email).

## Scope

**In scope:**
- `skvil_kedavra_scan.py`, `skvil_kedavra_check.py`, `skvil_kedavra_verify.py`
- Pattern detection bypass — techniques not caught by the scanner
- Hash integrity bypass — composite hash or file hash manipulation
- Supply chain attacks via the skill installation mechanism
- API key handling or exfiltration via the client

**Out of scope:**
- Vulnerabilities in the global registry backend (report to security@skvil.com separately, noting "backend")
- Denial-of-service against the public API (rate limits are enforced server-side)
- Theoretical attacks requiring local code execution with user-level privileges
  (the scanner runs as the user — the threat model assumes the host is trusted)

## Safe Harbor

We consider good-faith security research conducted under this policy to be
authorized. We will not pursue legal action against researchers who:

- Report vulnerabilities promptly and in good faith
- Avoid accessing, modifying, or destroying user data
- Do not disrupt production services
- Give us reasonable time to fix issues before public disclosure

Thank you for helping keep Skvil and its users safe.
