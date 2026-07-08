"""Plain-text report generator."""

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
    if context.technologies:
        lines.append("── Technologies ──")
        if all(isinstance(t, dict) for t in context.technologies):
            for entry in context.technologies:
                source = entry.get("source", "?")
                server = entry.get("server") or "N/A"
                cms = ", ".join(entry.get("cms", [])) or "N/A"
                lines.append(f"  [{source}] Server: {server}  CMS: {cms}")
        else:
            for tech in context.technologies:
                lines.append(f"  {tech}")
        lines.append("")

    if not any([context.whois, context.dns, context.subdomains,
                context.open_ports, context.banners, context.technologies]):
        lines.append("  No results collected.")

    lines.append("=" * 60)
    return "\n".join(lines)
