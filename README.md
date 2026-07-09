# Recon-Tool

> A modular, pipeline-based passive and active reconnaissance framework for security assessments and penetration testing.

---

## What

**Recon-Tool** is an automated information-gathering tool that collects intelligence about a target domain through three phases:

| Phase | Description | Modules |
|---|---|---|
| **Passive Reconnaissance** | Collects data without touching the target infrastructure | WHOIS, DNS, Subdomains |
| **Active Reconnaissance** | Connects directly to the target to enumerate services | Port Scan, Banner Grab |
| **Technology Fingerprinting** | Identifies software, frameworks, and analytics | Tech Detect (3 layers) |

Each phase enriches a shared `Context` object. When all phases complete, the `Context` is rendered into a report.

---

## Why

### Problem

Security assessments begin with reconnaissance, yet most existing tools are:

- **Monolithic** — tightly coupled code that is hard to extend or maintain
- **Single-purpose** — one tool for WHOIS, another for DNS, a third for port scanning
- **CLI-inconsistent** — each tool has its own flags, output format, and behaviour
- **Difficult to automate** — no shared state between tools; output is text meant for humans, not machines

### Solution

Recon-Tool solves these by:

- **Modular architecture** — every reconnaissance technique is a self-contained class implementing `BaseReconModule`
- **Unified pipeline** — all modules share a single `Context` object; each reads from it and writes to it
- **Consistent CLI** — the same `--output text | html` flag works for every combination of modules
- **Pluggable design** — adding a new technique means writing one class; the engine and report layers adapt automatically

---

## How

### Data Flow

```
CLI Input
  │
  ├── main.py
  │     ├── parse_args()        ← reads CLI flags
  │     ├── Context(target)     ← creates the shared state object
  │     └── Engine(modules)     ← injects the selected module list
  │
  ├── Engine.run(context)
  │     │
  │     │   for each module:
  │     │     ├── validate(context) → bool
  │     │     │     Side-effect-free check. Returns False to skip.
  │     │     │
  │     │     └── run(context) → None
  │     │           Mutates context in-place with results.
  │     │           Never returns a value.
  │     │
  │     └── return context       ← enriched with all findings
  │
  ├── Context
  │     ├── target: str
  │     ├── whois: dict          ← populated by WhoisModule
  │     ├── dns: dict            ← populated by DnsModule
  │     ├── subdomains: list     ← populated by SubdomainsModule
  │     ├── open_ports: list     ← populated by PortScanModule
  │     ├── banners: list        ← populated by BannerGrabModule
  │     ├── technologies: list   ← populated by TechDetectModule
  │     └── data: dict           ← free-form extension
  │
  └── reports/*.py
        └── generate(context)
              Reads Context, renders text or HTML.
```

### Architecture Decisions

| Decision | Rationale |
|---|---|
| **Context as a dataclass** | Immutable structure, clear contract, type-checked fields |
| **validate() before run()** | Fail fast — skip modules whose preconditions are not met without wasting time |
| **run() returns None** | Forces modules to write results into Context, making the full result set available to every downstream component |
| **Engine continues on exception** | A single module failure never aborts the entire scan |
| **Centralised logging via root logger** | Every `logging.getLogger(__name__)` call shares one configuration — console + file |
| **Lazy imports** | `nmap`, `Wappalyzer`, report generators imported only when needed — no hard dependencies |
| **3-tier tech detection** | WhatWeb (most accurate) → Wappalyzer (offline) → Python fallback (always works) — graceful degradation |

### When to Use Each Module

| Module | Best for | Notes |
|---|---|---|
| `--whois` | Domain registration intelligence | Registrar, dates, name servers, DNSSEC |
| `--dns` | Infrastructure mapping | A/AAAA/MX/TXT/NS/SOA/PTR records |
| `--subdomains` | Attack surface expansion | Uses crt.sh + HackerTarget (passive only) |
| `--ports` | Service discovery | Nmap SYN scan (fallback to connect scan) |
| `--banner` | Service versioning | Protocol-aware probes per port, TLS fallback on 80 |
| `--tech` | Technology profiling | WhatWeb → Wappalyzer → regex fallback |

### When NOT to use

- **Stealth assessments** — `--ports` uses Nmap which can trigger IDS alerts. Use passive modules (`--whois --dns --subdomains`) for quiet reconnaissance.
- **Internal networks without permission** — active modules connect directly to the target. Always obtain written authorisation.
- **Real-time monitoring** — the tool is designed for point-in-time assessments, not continuous monitoring.

---

## Key Features

| Feature | Detail |
|---|---|
| **Protocol-aware banner grabbing** | Custom probes per port — SMTP EHLO, HTTP HEAD, IMAP CAPABILITY, etc. |
| **TLS fallback on port 80** | If a plain HTTP request returns empty, retries over TLS |
| **3-layer tech detection** | WhatWeb → Wappalyzer → regex fallback. Each layer covers the next |
| **SYN→Connect scan fallback** | Nmap starts with `-sS` (requires root); falls back to `-sT` automatically |
| **HTML report** | Cyberpunk-themed, dark-mode, responsive, self-contained page |
| **URL→domain cleaning** | Pass `http://example.com/path` — the tool strips protocol and path |
| **Passive-only mode** | Omit `--ports --banner --tech` to avoid touching the target |

---

## Quick Start

```bash
git clone https://github.com/exploiter-taz/Recon-Tool.git
cd Recon-Tool
python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
pip install python-nmap                    # optional — for --ports
sudo apt install whatweb -y               # optional — for --tech

# Passive scan only
python main.py example.com --whois --dns --subdomains --output text

# Full scan
python main.py example.com --all --output text

# HTML report
python main.py google.com --whois --dns --subdomains --output html > report.html
```

---

## CLI Reference

```text
positional:
  target                  Target domain or IP address

optional:
  --whois                 Perform WHOIS lookup
  --dns                   Perform DNS enumeration
  --subdomains            Enumerate subdomains
  --ports                 Scan open ports (requires nmap)
  --banner                Grab service banners
  --tech                  Detect web technologies
  --all                   Enable every available module
  --output {html,text}    Report format (default: text)
```

---

## Future Work

- **Asynchronous execution** — I/O-bound modules (DNS, subdomains, banner) could run concurrently for significant speed gains
- **Output to JSON/CSV** — structured data for integration with other tools
- **Custom wordlist for subdomains** — active brute-force subdomain enumeration via DNS
- **Vulnerability scanning** — correlate banner versions with known CVEs
- **Scope definition** — CIDR range expansion for network-wide scans
- **Screenshots** — headless browser for visual recon
- **Plugin registry** — community-contributed modules via a simple configuration file

---

## Architecture

```
modules/
├── base.py                 Abstract base class (BaseReconModule)
├── active/
│   ├── portscan.py         TCP port scanner via python-nmap
│   ├── banner.py           Service banner grabber with TLS fallback
│   └── techdetect.py       3-tier technology fingerprinting
└── passive/
    ├── whois.py            WHOIS domain lookup
    ├── dns.py              DNS record enumeration
    └── subdomains.py       Passive subdomain discovery

core/
├── context.py              Shared state dataclass
├── engine.py               Pipeline orchestrator
└── logger.py               Centralised logging

reports/
├── text.py                 Plain-text report
└── html.py                 HTML report (dark theme)

docs/
└── module_contract.md      Developer guide for writing modules
```

---

## License

This project is developed for educational and professional security assessment purposes. Use responsibly.
