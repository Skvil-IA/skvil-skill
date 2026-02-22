# 🦞 Skvil — Security Scanner for AI Agent Skills

Skvil is a security scanner built specifically for the AI agent ecosystem.
It analyzes skills before and after installation, tracks their reputation across
the global network, and detects tampering at every stage of the skill lifecycle.

---

## The Problem

AI agent skills are code that runs with real permissions — accessing files,
making network requests, executing commands. Yet most agents install them with
zero scrutiny. A malicious skill can exfiltrate credentials, establish reverse
shells, inject instructions into your agent, or quietly replace the scanner
checking it.

Skvil exists to close that gap.

---

## Layers of Protection

Skvil operates across three layers, each catching what the previous one misses.

### Layer 1 — Static Analysis (local, instant)

Before a skill runs a single line of code, Skvil scans its source for over 30
behavioral patterns across 10 risk categories:

| Category | What it detects |
|---|---|
| `network` | Outbound connections, HTTP clients, socket usage |
| `credentials` | Access to `.env`, key files, secrets in environment |
| `shell` | Command execution via subprocess, eval, os.system |
| `file_access` | Reads outside skill directory, path traversal |
| `obfuscation` | Base64-decoded exec, encoded payloads, dynamic imports |
| `reverse_shell` | Shell-over-socket patterns, PTY allocation |
| `prompt_injection` | Embedded instructions targeting the host agent |
| `deserialization` | pickle.loads, yaml.load, untrusted deserialization |
| `native_code` | ctypes, cffi, direct memory access |
| `environment` | Reading PATH, SHELL, HOME; env manipulation |

Each finding has a severity (`critical`, `high`, `medium`, `low`) and maps to a
score from 0–100. The score reflects how much risk the static analysis found —
not a final verdict.

### Layer 2 — Integrity Verification (cryptographic, continuous)

Every file in a skill is hashed with SHA-256. These hashes are combined into a
single deterministic `composite_hash` that uniquely fingerprints the skill at a
given state.

This hash is used for:

- **TOCTOU protection** — a skill checked at URL `A` and installed at URL `A`
  may not be the same code if someone pushed between your check and your clone.
  Skvil verifies the hash post-install and alerts if they differ.
- **Tamper detection** — skills can modify their own files after the initial
  scan. Periodic re-verification catches post-install drift.
- **Scanner integrity** — every Skvil output includes the scanner's own hash.
  If Skvil itself is replaced by a malicious impostor, the hash won't match.

### Layer 3 — Global Reputation Network (collective intelligence)

When Skvil submits a scan to the global registry, it contributes to a shared
reputation score for that skill's hash. Reputation is computed using an
Exponential Moving Average — recent scans carry more weight, old data decays.

A skill scanned by 500 agents over 3 months tells a very different story than
one scanned twice last week. Sybil protection limits how much any single key
can influence the EMA within a rolling window.

What the registry provides back:

- **Reputation score** — community-weighted 0–100
- **Total scans** — how widely the skill has been observed
- **Certification** — whether the skill carries an active verified status
- **Risk summary** — aggregate finding distribution across all scans
- **Confirmed malicious flag** — set when community reports are confirmed

---

## Usage

### Scan all installed skills

```
skvil scan
```

Discovers all skills in `~/.openclaw/skills/` and `./skills/`, runs full
static analysis on each, and fetches live reputation from the registry.

### Check a skill before installing

```
skvil check <github-url>
```

Clones the repo to a temporary directory, analyzes it without executing
anything, reports a score and recommendation, then deletes the clone.
The `composite_hash` in the output is the expected hash after install —
use it in the next step.

### Verify a specific skill

```
skvil verify <skill-name>
```

Recomputes the hash of an installed skill and compares it against the registry.
Use this after install (TOCTOU check) and periodically thereafter.

---

## Zero Dependencies

Skvil requires only Python 3.8+ and `git`. No package installation, no virtual
environments, no supply chain to compromise. The scanner itself is a skill —
it installs the same way as anything else, and you can verify its own integrity
before trusting its output.

---

## Connected Mode

On first run, Skvil automatically registers a free API key and saves it to
`~/.skvil/config`. No manual setup required.

In connected mode, every scan:
1. Submits findings and the composite hash to the global registry
2. Receives current reputation, certification status, and risk summary
3. Returns enriched output with `mode: "connected"`

If the registry is unreachable or registration fails (network error, rate
limit), Skvil falls back to local mode gracefully — static analysis still
runs, reputation data is simply unavailable for that scan.

To use a pre-existing key: set `SKVIL_KEDAVRA_API_KEY=<key>` or add
`api_key=<key>` to `~/.skvil/config`.

---

## Community Reporting

If you find a skill that Skvil scored as safe but you believe is malicious,
you can report it via `POST /report` on the API. Reports are reviewed and,
when confirmed, permanently flag the composite hash across the network —
affecting every agent that checks that skill going forward.

---

## Certification *(coming soon)*

Static analysis and reputation scoring answer *"what does this skill do?"* and
*"what does the community think?"* — but they cannot answer *"has this skill
been independently verified by a trusted third party?"*

The Skvil Certification Program will address this.

Certified skills undergo deep behavioral analysis in an isolated sandbox
environment — not just static pattern matching, but real runtime observation:
syscalls, network connections, file operations, memory access. The sandbox
observes what the skill *actually does* when executed, which is far harder to
fake than passing a static scan.

Certification levels planned:

| Level | Meaning |
|---|---|
| **V1** | Sandbox-verified: no malicious runtime behavior detected |
| **V2** | V1 + source audit by the Skvil security team |
| **V3** | V2 + reproducible build verification |
| **Gold** | Full audit + maintained long-term by a verified publisher |

A certified skill will carry a verifiable certification record tied to its
`composite_hash`. Any change to the skill's files invalidates the certification
— agents will detect this via hash mismatch before the skill runs.

---

## Security Notes

- `api_url` is never read from the config file — only from the environment
  variable `SKVIL_KEDAVRA_API_URL`. This prevents a malicious skill with
  file-write access from redirecting your scans to an attacker-controlled server.
- TLS is explicitly enforced regardless of environment variables that might
  disable certificate verification globally.
- Automatic redirect following is disabled to prevent server-side request
  forgery via crafted API responses.
- Git clones use `--depth 1`, hooks disabled, and a 30-second timeout with a
  50MB size cap.

---

## Registry

Global reputation data, certification records, and community reports are
maintained at [skvil.com](https://skvil.com).
