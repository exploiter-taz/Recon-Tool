"""HTML report generator — sci-fi themed visual output."""

import html as html_mod
from typing import Any

from core.context import Context

# ── Emoji / icon helpers ─────────────────────────────────────────────

_ICONS = {
    "whois": "&#x1F50D;",
    "dns": "&#x1F310;",
    "subdomains": "&#x1F433;",
    "ports": "&#x1F6E1;",
    "banners": "&#x1F4E1;",
    "tech": "&#x2699;",
    "target": "&#x1F3AF;",
    "time": "&#x23F0;",
    "server": "&#x1F5A5;",
}

_SECTION_COLORS = {
    "whois": "#00e5ff",
    "dns": "#76ff03",
    "subdomains": "#ffea00",
    "ports": "#ff1744",
    "banners": "#d500f9",
    "tech": "#00e676",
}

# ── Helpers ──────────────────────────────────────────────────────────


def _fmt(val: Any) -> str:
    """Format *val* for HTML — lists render as inner bullet lists."""
    if isinstance(val, list):
        items = "".join(
            f"<li style='margin:0.2rem 0'>{html_mod.escape(str(v))}</li>"
            for v in val
        )
        return f"<ul style='margin:0;padding-left:1.2rem;list-style:square'>{items}</ul>"
    return html_mod.escape(str(val))


def _card(
    icon: str,
    title: str,
    body: str,
    color: str,
    col_count: int | None = None,
) -> str:
    """Return a themed card section."""
    cols = f"style='grid-column:span {col_count}'" if col_count else ""
    return f"""\
<div class="card" {cols} style="border-left:4px solid {color}">
  <div class="card-header" style="color:{color}">
    <span class="icon">{icon}</span> {title}
  </div>
  <div class="card-body">{body}</div>
</div>"""


def _stat_box(label: str, value: str, color: str) -> str:
    """Mini stat box for the summary bar."""
    return f"""\
<div class="stat" style="border-left:3px solid {color}">
  <div class="stat-value">{value}</div>
  <div class="stat-label">{label}</div>
</div>"""


def _tag(text: str, color: str = "#00e5ff") -> str:
    return f"<span class='tag' style='background:{color}22;color:{color};border:1px solid {color}44'>{html_mod.escape(str(text))}</span>"


# ── Main generator ───────────────────────────────────────────────────


def generate_html_report(context: Context) -> str:
    """Render scan results as a self-contained HTML page.

    Args:
        context: The enriched context after all modules have run.

    Returns:
        A complete HTML document string.
    """
    target = html_mod.escape(context.target)

    # ── Summary stats ─────────────────────────────────────────────
    stats: list[str] = []
    if context.whois:
        stats.append(_stat_box("WHOIS Fields", str(len(context.whois)), _SECTION_COLORS["whois"]))
    if context.dns:
        total_records = sum(len(v) for v in context.dns.values())
        stats.append(_stat_box("DNS Records", str(total_records), _SECTION_COLORS["dns"]))
    if context.subdomains:
        stats.append(_stat_box("Subdomains", str(len(context.subdomains)), _SECTION_COLORS["subdomains"]))
    if context.open_ports:
        stats.append(_stat_box("Open Ports", str(len(context.open_ports)), _SECTION_COLORS["ports"]))
    if context.banners:
        stats.append(_stat_box("Banners", str(len(context.banners)), _SECTION_COLORS["banners"]))
    if context.technologies:
        total_tech = sum(
            len(t.get("cms", [])) + len(t.get("frameworks", []))
            + len(t.get("analytics", [])) + len(t.get("cdn", []))
            if isinstance(t, dict) else 1
            for t in context.technologies
        )
        stats.append(_stat_box("Technologies", str(total_tech or len(context.technologies)), _SECTION_COLORS["tech"]))

    summary_bar = f"""\
<div class="stats-row">
  {''.join(stats)}
</div>""" if stats else ""

    # ── Sections ──────────────────────────────────────────────────
    cards: list[str] = []

    # WHOIS
    if context.whois:
        rows = "".join(
            f"<tr><td class='key'>{html_mod.escape(str(k))}</td><td>{_fmt(v)}</td></tr>"
            for k, v in sorted(context.whois.items())
        )
        cards.append(_card(
            _ICONS["whois"], "WHOIS Lookup",
            f"<table class='data-table'>{rows}</table>",
            _SECTION_COLORS["whois"],
        ))

    # DNS
    if context.dns:
        items = "".join(
            f"<li><span class='dns-type'>{html_mod.escape(rtype)}</span> "
            f"<span class='dns-val'>{html_mod.escape(str(rec))}</span></li>"
            for rtype, records in context.dns.items()
            for rec in records
        )
        cards.append(_card(
            _ICONS["dns"], "DNS Records",
            f"<ul class='dns-list'>{items}</ul>",
            _SECTION_COLORS["dns"],
        ))

    # Subdomains
    if context.subdomains:
        items = "".join(
            f"<li>{html_mod.escape(sub)}</li>"
            for sub in context.subdomains[:100]
        )
        extra = f"<p class='muted' style='margin-top:0.5rem'>...and {len(context.subdomains) - 100} more</p>" if len(context.subdomains) > 100 else ""
        cards.append(_card(
            _ICONS["subdomains"], f"Subdomains ({len(context.subdomains)})",
            f"<ul class='grid-list'>{items}</ul>{extra}",
            _SECTION_COLORS["subdomains"],
        ))

    # Open Ports
    if context.open_ports:
        badges = " ".join(_tag(f"{p}/tcp", _SECTION_COLORS["ports"]) for p in context.open_ports)
        cards.append(_card(
            _ICONS["ports"], f"Open Ports ({len(context.open_ports)})",
            f"<div class='tags'>{badges}</div>",
            _SECTION_COLORS["ports"],
        ))

    # Banners
    if context.banners:
        items = ""
        for entry in context.banners:
            port = entry.get("port", "?")
            banner = entry.get("banner")
            if banner:
                preview = html_mod.escape(str(banner)[:100].replace("\n", " "))
                items += f"<li><span class='tag' style='background:#d500f922;color:#d500f9;border:1px solid #d500f944'>Port {port}</span> <code>{preview}</code></li>"
            else:
                err = html_mod.escape(str(entry.get("error", "N/A")))
                items += f"<li><span class='tag' style='background:#ff174422;color:#ff1744;border:1px solid #ff174444'>Port {port}</span> <span class='error'>{err}</span></li>"
        cards.append(_card(
            _ICONS["banners"], "Service Banners",
            f"<ul class='banner-list'>{items}</ul>",
            _SECTION_COLORS["banners"],
        ))

    # Technologies
    if context.technologies:
        items = ""
        if all(isinstance(t, dict) and "source" in t for t in context.technologies):
            for entry in context.technologies:
                source = html_mod.escape(str(entry.get("source", "?")))
                server = html_mod.escape(str(entry.get("server") or "N/A"))
                cms = [html_mod.escape(c) for c in entry.get("cms", [])]
                frameworks = [html_mod.escape(f) for f in entry.get("frameworks", [])]
                libraries = [html_mod.escape(l) for l in entry.get("libraries", [])]
                analytics = [html_mod.escape(a) for a in entry.get("analytics", [])]
                cdn = [html_mod.escape(c) for c in entry.get("cdn", [])]

                parts = []
                if server and server != "N/A":
                    parts.append(f"<span class='tag' style='background:#00e67622;color:#00e676'>{server}</span>")
                for c in cms:
                    parts.append(f"<span class='tag' style='background:#2979ff22;color:#2979ff'>CMS: {c}</span>")
                for f in frameworks:
                    parts.append(f"<span class='tag' style='background:#ff910022;color:#ff9100'>{f}</span>")
                for a in analytics:
                    parts.append(f"<span class='tag' style='background:#e040fb22;color:#e040fb'>Analytics: {a}</span>")
                for c in cdn:
                    parts.append(f"<span class='tag' style='background:#00bcd422;color:#00bcd4'>CDN: {c}</span>")

                items += f"<li><span class='source-badge'>{source}</span> {' '.join(parts)}</li>"
        else:
            for tech in context.technologies:
                items += f"<li>{html_mod.escape(str(tech))}</li>"

        cards.append(_card(
            _ICONS["tech"], "Technologies",
            f"<ul class='tech-list'>{items}</ul>",
            _SECTION_COLORS["tech"],
        ))

    body_content = "\n".join(cards) or "<p class='muted'>No results collected.</p>"

    # ── HTML template ─────────────────────────────────────────────
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Recon Report — {target}</title>
<style>
  {{| reset |}}
  *,*::before,*::after {{ margin:0;padding:0;box-sizing:border-box }}
  html {{ font-size:15px }}
  body {{
    font-family: 'SF Mono','Cascadia Code','Fira Code','Consolas',monospace;
    background: linear-gradient(135deg, #0a0e1a 0%, #111828 40%, #0d1b2a 100%);
    color: #c8d6e5;
    min-height: 100vh;
    padding: 2rem 1.5rem;
  }}

  {{| main container |}}
  .container {{ max-width:1200px;margin:0 auto }}

  {{| header |}}
  .hero {{
    text-align:center;padding:2.5rem 1rem 2rem;
    border-bottom:1px solid #ffffff0d;margin-bottom:2rem
  }}
  .hero h1 {{
    font-size:2.2rem;font-weight:700;letter-spacing:-0.5px;
    background: linear-gradient(135deg, #00e5ff 0%, #76ff03 50%, #d500f9 100%);
    -webkit-background-clip:text;-webkit-text-fill-color:transparent;
    background-clip:text
  }}
  .hero .sub {{ font-size:0.85rem;color:#6272a4;margin-top:0.5rem }}
  .hero .sub span {{ color:#00e5ff }}

  {{| stats row |}}
  .stats-row {{
    display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));
    gap:1rem;margin-bottom:2rem
  }}
  .stat {{
    background:#ffffff08;border-radius:8px;padding:1rem;
    backdrop-filter:blur(4px);text-align:center
  }}
  .stat-value {{ font-size:1.6rem;font-weight:700;color:#fff }}
  .stat-label {{ font-size:0.7rem;text-transform:uppercase;letter-spacing:1px;color:#6272a4;margin-top:0.25rem }}

  {{| cards grid |}}
  .cards {{
    display:grid;grid-template-columns:repeat(auto-fit,minmax(380px,1fr));
    gap:1.25rem;align-items:start
  }}
  .card {{
    background: linear-gradient(135deg, #ffffff06 0%, #ffffff03 100%);
    border-radius:12px;padding:0;overflow:hidden;
    backdrop-filter:blur(8px);box-shadow:0 4px 24px #00000066;
    transition:transform 0.2s,box-shadow 0.2s
  }}
  .card:hover {{ transform:translateY(-2px);box-shadow:0 8px 40px #00000099 }}
  .card-header {{
    font-size:0.85rem;font-weight:600;text-transform:uppercase;
    letter-spacing:1.5px;padding:1rem 1.25rem 0.5rem;
    border-bottom:1px solid #ffffff08
  }}
  .card-header .icon {{ font-size:1.1rem;margin-right:0.4rem }}
  .card-body {{ padding:0.75rem 1.25rem 1.25rem }}

  {{| tables |}}
  .data-table {{ width:100%;border-collapse:collapse;font-size:0.82rem }}
  .data-table td {{ padding:0.4rem 0.5rem;border-bottom:1px solid #ffffff08;vertical-align:top }}
  .data-table .key {{ color:#6272a4;white-space:nowrap;width:1px;padding-right:1rem }}
  .data-table tr:last-child td {{ border:none }}

  {{| lists |}}
  .dns-list,.banner-list,.tech-list {{ list-style:none;padding:0 }}
  .dns-list li,.banner-list li,.tech-list li {{ padding:0.3rem 0;border-bottom:1px solid #ffffff08;font-size:0.82rem }}
  .dns-list li:last-child,.banner-list li:last-child,.tech-list li:last-child {{ border:none }}
  .dns-type {{ display:inline-block;min-width:3.5rem;font-weight:600;color:#76ff03 }}
  .dns-val {{ color:#c8d6e5;word-break:break-all }}
  code {{ background:#ffffff08;padding:0.1rem 0.4rem;border-radius:4px;font-size:0.8rem;word-break:break-all }}

  {{| grid list for subdomains |}}
  .grid-list {{
    display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));
    gap:0.3rem 0.75rem;list-style:none;padding:0;font-size:0.8rem
  }}
  .grid-list li {{ padding:0.15rem 0;color:#c8d6e5 }}
  .grid-list li::before {{ content:"▸ ";color:#6272a4 }}

  {{| tags / badges |}}
  .tags {{ display:flex;flex-wrap:wrap;gap:0.5rem }}
  .tag {{
    display:inline-block;padding:0.2rem 0.6rem;border-radius:20px;
    font-size:0.75rem;font-weight:500;letter-spacing:0.3px
  }}
  .source-badge {{
    display:inline-block;padding:0.15rem 0.5rem;border-radius:4px;
    background:#ffffff0d;font-size:0.7rem;text-transform:uppercase;
    color:#6272a4;margin-right:0.5rem
  }}
  .error {{ color:#ff1744;font-size:0.8rem }}
  .muted {{ color:#6272a4;font-size:0.8rem }}

  {{| responsive |}}
  @media (max-width:600px) {{
    .cards {{ grid-template-columns:1fr }}
    .grid-list {{ grid-template-columns:1fr }}
    html {{ font-size:14px }}
  }}
</style>
</head>
<body>
<div class="container">
  <div class="hero">
    <h1>&#x1F50D; Recon Report</h1>
    <div class="sub"><span>{target}</span> &middot; passive reconnaissance scan</div>
  </div>
  {summary_bar}
  <div class="cards">
    {body_content}
  </div>
</div>
</body>
</html>"""
