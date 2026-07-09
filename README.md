# Recon-Tool

> A recon tool that actually makes sense. Give it a domain, get back everything.

---

## What is this?

You give it `example.com`.

It tells you who owns it, what servers it runs on, what ports are open, what tech stack is behind it, and a bunch of other things you would otherwise have to run five different tools to find out.

It is built for:
- Penetration testers who want to automate the boring part
- Security researchers mapping out infrastructure
- Anyone who has ever had to manually run whois + dig + nmap + whatweb separately

---

## What kind of stuff does it find?

| Thing | What you get | Real example |
|---|---|---|
| **WHOIS** | Who owns the domain, when it was registered | Google LLC, MarkMonitor, 1997 |
| **DNS** | IP addresses, mail servers, name servers | `142.250.181.142`, `ns1.google.com` |
| **Subdomains** | Other domains hanging off the same root | `mail.google.com`, `docs.google.com` |
| **Open ports** | Which doors are open on the server | Port 80 (HTTP), Port 22 (SSH) |
| **Banners** | What software is actually running on those ports | `nginx 1.24.0` |
| **Technologies** | What stack the website is built on | Cloudflare, React, Google Analytics |

---

## Why does this exist?

If you have done any recon work, you know the pain:

- One tool for WHOIS. One for DNS. One for ports. One for tech detection.
- Each one has different flags, different output formats, different everything.
- None of them talk to each other.
- You end up copying and pasting output between terminals like a caveman.

This tool puts everything in one pipeline. One command, one output, one shared state that every module reads from and writes to. Add a new module? Write one class. That is it.

---

## How does it actually work?

Run this:

```bash
python main.py example.com --whois --dns --ports --output text
```

Here is what happens under the hood, step by step.

---

### Step 1 — main.py starts

It does a few things before anything else:

- Sets up logging so all output goes to the same place.
- Reads your command: `target = example.com`, modules = `--whois --dns --ports`.
- Strips junk — if you passed `http://example.com/blah`, it keeps just `example.com`.
- Creates a `Context` object. Think of it as an empty backpack labelled `example.com`.

### Step 2 — Modules get picked

Each flag maps to a module:

```
--whois  →  WhoisModule
--dns    →  DnsModule
--ports  →  PortScanModule
```

Order matters. Passive stuff comes first, active stuff later. Some modules depend on others — for example, banner grabbing needs port scan results first, so it runs after.

### Step 3 — The Engine runs them

The engine does not care what each module does. It just knows every module has two functions: `validate()` and `run()`.

```
for each module:
    validate(backpack)   ←  Can I run? Is everything I need here?
         ↓ if True
    run(backpack)        ←  Do the thing, write results into backpack
         ↓ if error
    log it, move on      ←  One module crash never kills the whole scan
```

### Step 4 — The backpack fills up

```
After WhoisModule:   backpack contains target + whois data
After DnsModule:     backpack contains whois + dns data
After PortScanModule: backpack contains whois + dns + open ports
```

Each module sees what the ones before it found. If `BannerGrabModule` ran, it would see `open_ports` and grab banners for each one.

### Step 5 — Report comes out

The backpack gets handed to a report generator:

```python
report = generate_text_report(backpack)
print(report)
```

The report generator does not scan anything. It just reads whatever is in the backpack and formats it nicely.

Here is a picture of the whole pipeline:

```
You:  python main.py example.com --whois --dns --ports
        │
        ▼
  main.py
        │
        ├── parse flags
        ├── create empty backpack
        │
        ▼
  Engine runs:
        │
        ├── WhoisModule
        │     ├── validate(backpack)  →  ok
        │     └── run(backpack)       →  adds whois data
        │
        ├── DnsModule
        │     ├── validate(backpack)  →  ok
        │     └── run(backpack)       →  adds dns records
        │
        └── PortScanModule
              ├── validate(backpack)  →  ok
              └── run(backpack)       →  adds open ports
        │
        ▼
  backpack has: { target, whois, dns, open_ports }
        │
        ▼
  Report generator reads it →
        ┌──────────────────────────────────────┐
        │         RECON REPORT                  │
        │  example.com                          │
        │                                       │
        │  [ WHOIS ]       Google LLC, ...      │
        │  [ DNS ]         142.250.x.x, ...     │
        │  [ OPEN PORTS ]  80/tcp, 443/tcp      │
        └──────────────────────────────────────┘
```

---

### Why things are designed this way

| Choice | Why |
|---|---|
| **validate() before run()** | No point scanning ports if the target did not resolve. Fail fast, skip cleanly. |
| **run() does not return anything** | Everything goes into the backpack. No lost data, no missed return values. |
| **Engine keeps going on errors** | One API timeout should not trash your whole scan. |
| **Centralised logging** | Every module logs to the same place without extra setup. |
| **Lazy imports** | nmap, Wappalyzer, report generators are only imported when needed. No hard failures on missing tools. |
| **3-layer tech detection** | WhatWeb is best, Wappalyzer works offline, the fallback always runs. Something always comes back. |

---

### When each module is useful

| Flag | Use it when | Notes |
|---|---|---|
| `--whois` | You want to know who owns the domain | Registrar, dates, DNSSEC status |
| `--dns` | You are mapping infrastructure | A, AAAA, MX, TXT, NS, SOA, PTR |
| `--subdomains` | You want to expand the attack surface | Uses crt.sh + HackerTarget, fully passive |
| `--ports` | You want to find open services | Uses nmap SYN scan, falls back to connect scan |
| `--banner` | You want version numbers of services | Protocol-aware probes per port |
| `--tech` | You want to know the tech stack | Three detection engines, falls back gracefully |

### When NOT to use this

- **If you need to stay under the radar** — skip `--ports --banner --tech`. Active modules touch the target and can trigger alarms.
- **If you do not have permission** — do not run this against something you do not own. Seriously.
- **If you need continuous monitoring** — this is built for one-shot assessments, not 24/7 watching.

---

## What makes this different

| Thing | Why it matters |
|---|---|
| **Banner grabbing knows the protocol** | Each port gets the right probe — SMTP gets EHLO, HTTP gets HEAD, IMAP gets CAPABILITY. Not a generic connect-and-hope. |
| **TLS fallback on port 80** | If a plain HTTP request comes back empty, it retries over TLS. Catches sites that force HTTPS. |
| **Tech detection has three layers** | WhatWeb → Wappalyzer → regex fallback. One of them will work. |
| **Nmap falls back if you are not root** | Tries `-sS` first, falls back to `-sT` if it needs to. |
| **HTML report does not look like a terminal vomit** | Dark theme, cards, colour-coded tags. Open it in a browser and it actually looks good. |
| **You can paste a full URL** | `http://example.com/page` works. It strips the protocol and path automatically. |
| **Passive-only mode** | Just leave out `--ports --banner --tech` and you never touch the target. |

---

## Get started

```bash
git clone https://github.com/exploiter-taz/Recon-Tool.git
cd Recon-Tool
python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
pip install python-nmap              # needed for --ports
sudo apt install whatweb -y         # needed for better --tech results

# Passive scan — does not touch the target
python main.py example.com --whois --dns --subdomains --output text

# Everything
python main.py example.com --all --output text

# Save an HTML report
python main.py google.com --whois --dns --subdomains --output html > report.html
```

---

## CLI at a glance

```text
positional:
  target                   Domain or IP

optional:
  --whois                  WHOIS lookup
  --dns                    DNS enumeration
  --subdomains             Subdomain enumeration
  --ports                  Port scan (needs nmap)
  --banner                 Banner grabbing
  --tech                   Technology detection
  --all                    Enable everything
  --output {html,text}     Report format (default: text)
```

---

## What could come next

- **Async mode** — DNS and subdomain lookups are waiting-on-network work. They could run in parallel and finish faster.
- **JSON/CSV output** — so other tools can consume the results.
- **Subdomain brute force** — use a wordlist instead of just passive sources.
- **CVE lookup** — match banner versions against known vulnerabilities.
- **CIDR expansion** — scan whole networks, not just single domains.
- **Plugin system** — drop a module file in a folder, and it is picked up automatically.

---

## Project layout

```
modules/
├── base.py                 What every module looks like
├── active/
│   ├── portscan.py         TCP port scanner
│   ├── banner.py           Service banner grabber
│   └── techdetect.py       3-tier tech detection
└── passive/
    ├── whois.py            WHOIS lookup
    ├── dns.py              DNS records
    └── subdomains.py       Subdomain discovery

core/
├── context.py              The backpack
├── engine.py               Runs modules in order
└── logger.py               Logging setup

reports/
├── text.py                 Terminal report
└── html.py                 HTML report

docs/
└── module_contract.md      How to write a module
```

---

## One more thing

This is built for learning and professional work. Use it on things you own or have permission to test. Not because I am saying that to sound responsible — because it is literally a tool that connects to other people's servers and asks them questions. Be smart about it.

---

*Last updated: 2026-07-08*
