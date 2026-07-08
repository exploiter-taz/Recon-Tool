"""Plain-text report generator."""

from collections import defaultdict
from typing import Any

from core.context import Context


def generate_text_report(context: Context) -> str:
    """Render scan results as a human-readable text report.

    Args:
        context: The enriched context after all modules have run.

    Returns:
        A formatted plain-text string.
    """
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append(f"  Recon Report — {context.target}")
    lines.append("=" * 60)
    lines.append("")

    # WHOIS
    if context.whois:
        lines.append("── WHOIS ──")
        for key, value in context.whois.items():
            lines.append(f"  {key}: {value}")
        lines.append("")

    # DNS
    if context.dns:
        lines.append("── DNS Records ──")
        for rtype, records in context.dns.items():
            for record in records:
                lines.append(f"  {rtype}: {record}")
        lines.append("")

    # Subdomains
    if context.subdomains:
        lines.append("── Subdomains ──")
        for sub in context.subdomains:
            lines.append(f"  {sub}")
        lines.append("")

    # Open ports
    if context.open_ports:
        lines.append("── Open Ports ──")
        for port in context.open_ports:
            lines.append(f"  {port}/tcp")
        lines.append("")

    # Banners
    if context.banners:
        lines.append("── Service Banners ──")
        for entry in context.banners:
            port = entry.get("port", "?")
            banner = entry.get("banner", "N/A")
            if banner:
                preview = banner[:80].replace("\n", " ")
            else:
                preview = entry.get("error", "N/A")
            lines.append(f"  Port {port}: {preview}")
        lines.append("")

    # Technologies
    lines.extend(_render_technologies(context))

    if not any([context.whois, context.dns, context.subdomains,
                context.open_ports, context.banners, context.technologies]):
        lines.append("  No results collected.")

    lines.append("=" * 60)
    return "\n".join(lines)


def _render_technologies(context: Context) -> list[str]:
    """Render the Technologies, Detection Sources, and Summary sections."""
    lines: list[str] = []
    if not context.technologies:
        return lines

    # ── Aggregate across all sources ──────────────────────────────
    categories = ["server", "cms", "frameworks", "libraries", "analytics", "cdn"]
    source_names = {"whatweb": "WhatWeb", "wappalyzer": "Wappalyzer", "fallback": "HTTP Fallback"}

    values: dict[str, set[str]] = {c: set() for c in categories}
    value_sources: dict[str, dict[str, set[str]]] = {c: defaultdict(set) for c in categories}
    active_sources: set[str] = set()

    for entry in context.technologies:
        if not isinstance(entry, dict):
            continue
        src_raw = entry.get("source", "")
        src = source_names.get(src_raw, src_raw.capitalize())
        active_sources.add(src)

        for cat in categories:
            raw = entry.get(cat)
            if not raw:
                continue
            items = raw if isinstance(raw, list) else [raw]
            for item in items:
                text = str(item).strip()
                if text:
                    values[cat].add(text)
                    value_sources[cat][text].add(src)

    # ── Technologies section ──────────────────────────────────────
    lines.append("Technology Fingerprint")
    lines.append("=" * 49)

    category_labels = {
        "server": "Server",
        "cms": "CMS",
        "frameworks": "Frameworks",
        "libraries": "Libraries",
        "analytics": "Analytics",
        "cdn": "CDN",
    }

    for cat in categories:
        label = category_labels[cat]
        lines.append("")
        lines.append(f"  {label}")
        if values[cat]:
            for val in sorted(values[cat]):
                lines.append(f"    \u2022 {val}")
        else:
            lines.append(f"    Not detected")

    # ── Detection Sources section ─────────────────────────────────
    lines.append("")
    lines.append("  Detection Sources")
    lines.append("  " + "-" * 30)
    all_known = ["WhatWeb", "Wappalyzer", "HTTP Fallback"]
    for name in all_known:
        if name in active_sources:
            lines.append(f"    \u2713 {name}")
        else:
            lines.append(f"    \u2717 {name}")

    # ── Summary section ───────────────────────────────────────────
    lines.append("")
    lines.append("  Summary")
    lines.append("  " + "-" * 30)

    total_detections = sum(len(v) for v in values.values())
    detected_categories = [category_labels[c] for c in categories if values[c]]
    lines.append(f"    Technologies found:       {total_detections}")
    lines.append(f"    Categories with data:     {', '.join(detected_categories) if detected_categories else 'None'}")
    lines.append(f"    Active detection sources: {len(active_sources)}/{len(all_known)} ({', '.join(sorted(active_sources))})")

    lines.append("")
    return lines
