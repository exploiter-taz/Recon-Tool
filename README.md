# Recon-Tool

> A modular, pipeline-based passive and active reconnaissance framework for security assessments and penetration testing.

---

## What

**Recon-Tool** is an automated information-gathering tool. You give it a domain name (like `example.com`), and it finds out as much as it can about that domain — who owns it, what servers it runs, what ports are open, what technologies are behind it, and more.

It is designed for **security researchers, penetration testers, and system administrators** who need to understand a target's digital footprint before performing deeper analysis.

### What kind of information does it collect?

| Category | What you learn | Example |
|---|---|---|
| **WHOIS** | Who registered the domain, when, contact info | Google LLC, MarkMonitor, 1997-09-15 |
| **DNS** | IP addresses, mail servers, name servers, TXT records | 142.250.181.142, ns1.google.com |
| **Subdomains** | Other domains under the same root | mail.google.com, docs.google.com |
| **Open Ports** | What doors (ports) are open on the server | Port 80 (HTTP), Port 22 (SSH) |
| **Banners** | What software is running on each open port | nginx/1.24.0 (Ubuntu) |
| **Technologies** | What tech stack the website uses | Cloudflare, React, Google Analytics |

### Three phases of reconnaissance

The tool operates in three ordered phases. Each phase depends on data from the previous one:

| Phase | What it does | Modules | Touches the target? |
|---|---|---|---|
| **1. Passive Recon** | Gathers info from public databases | WHOIS, DNS, Subdomains | ❌ No — uses APIs only |
| **2. Active Recon** | Connects directly to the target | Port Scan, Banner Grab | ✅ Yes — makes network connections |
| **3. Fingerprinting** | Analyses collected data to identify software | Tech Detect | ✅ Yes — sends HTTP requests |

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

### Step by step: What happens when you type the command?

Imagine you run:

```bash
python main.py example.com --whois --dns --ports --output text
```

Here is exactly what happens, from the moment you press Enter to the moment you see the results:

---

#### Step 1 — `main.py` wakes up

The file `main.py` is the entry point. It does four things immediately:

1. **Calls `setup_logger()`** — configures logging so every component writes to the same place (terminal + file).
2. **Calls `parse_args()`** — reads your command-line arguments (`target = example.com`, `--whois`, `--dns`, `--ports`, `--output text`).
3. **Cleans the target** — if you passed `http://example.com/path`, it strips the protocol and path and keeps just `example.com`.
4. **Creates the `Context`** — an object that starts with only `target = "example.com"` and every other field set to `None` (empty).

---

#### Step 2 — Modules are selected

Based on your flags, `main.py` builds a list of modules:

- `--whois`  →  `WhoisModule` (passive)
- `--dns`    →  `DnsModule` (passive)
- `--ports`  →  `PortScanModule` (active)

Order matters. Passive modules come first, then active ones. Some modules **depend** on others — for example, `BannerGrabModule` needs `open_ports` from `PortScanModule`, so it must run after it.

---

#### Step 3 — The Engine takes over

```python
engine = Engine([WhoisModule(), DnsModule(), PortScanModule()])
engine.run(context)
```

The `Engine` is the orchestrator. It does not know what each module does. It only knows that every module has two methods: `validate()` and `run()`.

For each module in the list, the engine:

1. **Calls `module.validate(context)`**
   - The module inspects the `Context`.
   - If something critical is missing, it returns `False` and the module is skipped.
   - *Example:* `BannerGrabModule.validate()` checks: is `context.open_ports` set? If not, skip.
   - **Important:** `validate()` is read-only — it never modifies the `Context`.

2. **Calls `module.run(context)`**
   - The module does its actual work.
   - It reads what it needs from the `Context` and **writes its results back**.
   - *Example:* `WhoisModule` reads `context.target`, queries the WHOIS server, and sets `context.whois = { ... }`.
   - `run()` never returns a value. All output goes directly into the `Context`.

3. **If something goes wrong**
   - The module catches its own errors (timeout, connection refused, rate limit).
   - If it cannot handle the error, it lets it propagate. The engine catches it, logs the error, and **moves to the next module**.
   - One failing module never stops the entire scan.

---

#### Step 4 — The Context grows

After each module runs, the `Context` has more data:

```
After WhoisModule:     context.target = "example.com"
                       context.whois  = { registrar, dates, name_servers, ... }

After DnsModule:       context.dns    = { A: [...], MX: [...], NS: [...], ... }
                       context.whois  = (still there from before)

After PortScanModule:  context.open_ports = [22, 80, 443]
                       context.dns    = (still there)
                       context.whois  = (still there)
                       context.banners = (still None — we did not ask for banners)
```

Think of the `Context` as a **backpack** that starts empty. Each module opens the backpack, takes what it needs, and puts its findings inside. The next module sees everything the previous modules put in.

---

#### Step 5 — The Report is generated

Once all modules finish, the enriched `Context` is sent to a report generator:

```python
report = generate_text_report(context)
print(report)
```

The report generator reads the final state of the `Context` and formats it as:

- **Text** — a clean, readable terminal report.
- **HTML** — a styled, dark-mode page with cards, color-coded tags, and a summary.

The report generator never runs scans or touches the network. It only reads what is already in the `Context`.

---

### Visual summary of the pipeline

```
You type:  python main.py example.com --whois --dns --ports
                │
                ▼
          main.py
                │
                ├── parse_args()        →  reads --whois --dns --ports
                ├── Context(target)     →  creates an empty backpack
                │
                ▼
          Engine.run(backpack)
                │
                ├── WhoisModule
                │     ├── validate(backpack)  →  has a target?  Yes → proceed
                │     └── run(backpack)       →  writes whois data
                │
                ├── DnsModule
                │     ├── validate(backpack)  →  has a target?  Yes → proceed
                │     └── run(backpack)       →  writes dns records
                │
                └── PortScanModule
                      ├── validate(backpack)  →  has a target?  Yes → proceed
                      └── run(backpack)       →  writes open ports
                │
                ▼
          backpack is now full:
          { target, whois: {...}, dns: {...}, open_ports: [...] }
                │
                ▼
          Report generator reads backpack → formatted output →
          ============================================================
            RECON REPORT: example.com
          ============================================================
            [ WHOIS ]      registrar, dates, name servers...
            [ DNS ]        A records, MX, NS...
            [ OPEN PORTS ] 22/tcp, 80/tcp, 443/tcp
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
