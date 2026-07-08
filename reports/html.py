"""HTML report generator."""

import html as html_mod
from typing import Any

from core.context import Context


def generate_html_report(context: Context) -> str:
    """Render scan results as a self-contained HTML page.

    Args:
        context: The enriched context after all modules have run.

    Returns:
        An HTML string.
    """
    target = html_mod.escape(context.target)
    sections: list[str] = []

    def _section(title: str, body: str) -> str:
        return f"<h2>{title}</h2>\n{body}"

    def _fmt(val: Any) -> str:
        """Format a value for HTML display — lists become inner lists."""
        if isinstance(val, list):
            items = "".join(f"<li>{html_mod.escape(str(v))}</li>" for v in val)
            return f"<ul style='margin:0;padding-left:1.2rem'>{items}</ul>"
        return html_mod.escape(str(val))

    # WHOIS
    if context.whois:
        rows = "".join(
            f"<tr><td>{html_mod.escape(str(k))}</td><td>{_fmt(v)}</td></tr>"
            for k, v in context.whois.items()
        )
        sections.append(_section("WHOIS", f"<table>{rows}</table>"))

    # DNS
    if context.dns:
        items = "".join(
            f"<li><strong>{html_mod.escape(rtype)}:</strong> "
            f"{html_mod.escape(str(rec))}</li>"
            for rtype, records in context.dns.items()
            for rec in records
        )
        sections.append(_section("DNS Records", f"<ul>{items}</ul>"))

    # Subdomains
    if context.subdomains:
        items = "".join(
            f"<li>{html_mod.escape(sub)}</li>" for sub in context.subdomains
        )
        sections.append(_section("Subdomains", f"<ul>{items}</ul>"))

    # Open ports
    if context.open_ports:
        items = "".join(
            f"<li>{port}/tcp</li>" for port in context.open_ports
        )
        sections.append(_section("Open Ports", f"<ul>{items}</ul>"))

    # Banners
    if context.banners:
        items = ""
        for entry in context.banners:
            port = entry.get("port", "?")
            banner = entry.get("banner") or entry.get("error", "N/A")
            preview = html_mod.escape(str(banner)[:80])
            items += f"<li>Port {port}: <code>{preview}</code></li>"
        sections.append(_section("Service Banners", f"<ul>{items}</ul>"))

    # Technologies
    if context.technologies:
        items = ""
        if all(isinstance(t, dict) for t in context.technologies):
            for entry in context.technologies:
                source = html_mod.escape(str(entry.get("source", "?")))
                server = html_mod.escape(str(entry.get("server") or "N/A"))
                cms = html_mod.escape(", ".join(entry.get("cms", [])) or "N/A")
                items += f"<li>[{source}] Server: {server} | CMS: {cms}</li>"
        else:
            for tech in context.technologies:
                items += f"<li>{html_mod.escape(str(tech))}</li>"
        sections.append(_section("Technologies", f"<ul>{items}</ul>"))

    body = "\n".join(sections) or "<p>No results collected.</p>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Recon Report — {target}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif;
         max-width: 900px; margin: 2rem auto; padding: 0 1rem; }}
  h1 {{ border-bottom: 2px solid #333; padding-bottom: 0.5rem; }}
  h2 {{ color: #2c3e50; margin-top: 1.5rem; }}
  table {{ border-collapse: collapse; width: 100%; }}
  td, th {{ border: 1px solid #ddd; padding: 0.5rem; text-align: left; }}
  tr:nth-child(even) {{ background: #f9f9f9; }}
  ul {{ padding-left: 1.5rem; }}
  li {{ margin: 0.25rem 0; }}
</style>
</head>
<body>
<h1>Recon Report — {target}</h1>
{body}
</body>
</html>"""
