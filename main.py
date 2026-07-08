"""Entry point for the Recon Tool."""

import argparse
import json
import logging
import sys
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urlparse

from cli import parse_args
from core.context import Context
from core.engine import Engine
from core.logger import setup_logger

logger = logging.getLogger(__name__)

CACHE_DIR = Path("cache")


def _build_module_list(args: argparse.Namespace) -> list:
    """Select modules based on CLI flags."""
    from modules.active.banner import BannerGrabModule
    from modules.active.portscan import PortScanModule
    from modules.active.techdetect import TechDetectModule
    from modules.passive.dns import DnsModule
    from modules.passive.subdomains import SubdomainsModule
    from modules.passive.whois import WhoisModule

    modules = []

    if args.all_modules:
        # Ordered: passive first, then active, then analysis
        modules = [
            WhoisModule(),
            DnsModule(),
            SubdomainsModule(),
            PortScanModule(),
            BannerGrabModule(),
            TechDetectModule(),
        ]
        return modules

    if args.whois:
        modules.append(WhoisModule())
    if args.dns:
        modules.append(DnsModule())
    if args.subdomains:
        modules.append(SubdomainsModule())
    if args.ports:
        modules.append(PortScanModule())
    if args.banner:
        modules.append(BannerGrabModule())
    if args.tech:
        modules.append(TechDetectModule())

    return modules


def _generate_report(context: Context, output_format: str) -> None:
    """Print or save results based on the chosen output format."""
    if output_format == "text":
        from reports.text import generate as generate_text_report

        report = generate_text_report(context)
    elif output_format == "html":
        from reports.html import generate_html_report

        report = generate_html_report(context)
    else:
        logger.error("Unknown output format: %s", output_format)
        return

    if report:
        print(report)


def _cache_path(target: str) -> Path:
    """Return the filesystem path for the cache file of *target*."""
    safe = target.replace(".", "_").replace(":", "_")
    return CACHE_DIR / f"{safe}.json"


def _load_cache(target: str) -> Context | None:
    """Load a previously cached scan result for *target*, or return None."""
    path = _cache_path(target)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        logger.info("Loaded cached results for %s", target)
        return Context(**data)
    except (json.JSONDecodeError, TypeError, KeyError) as exc:
        logger.warning("Cache corrupt for %s — %s", target, exc)
        return None


def _save_cache(context: Context) -> None:
    """Persist *context* to disk so future scans can skip re-execution."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = _cache_path(context.target)
    data = asdict(context)
    # Convert non-serializable values to strings
    raw = json.dumps(data, indent=2, default=str)
    path.write_text(raw)
    logger.info("Scan results cached for %s", context.target)


def _clean_target(raw: str) -> str:
    """Extract the hostname from a URL or return the raw string as-is."""
    parsed = urlparse(raw)
    if parsed.scheme and parsed.netloc:
        return parsed.netloc
    if parsed.scheme:
        return parsed.path.split("/")[0]
    return raw.split("/")[0]


def main() -> None:
    """Parse arguments, build pipeline, execute, and report results."""
    setup_logger()

    args = parse_args()

    # If no modules selected and --all not given, show help.
    if not any([args.whois, args.dns, args.subdomains, args.ports,
                args.banner, args.tech, args.all_modules]):
        parser = argparse.ArgumentParser(
            description="Reconnaissance tool for security assessments.",
        )
        parser.print_help()
        sys.exit(1)

    target = _clean_target(args.target)

    # Load cache or run fresh scan
    context = _load_cache(target) if not args.fresh else None

    if context is not None:
        _generate_report(context, args.output)
        return

    context = Context(target=target)
    modules = _build_module_list(args)

    if not modules:
        logger.warning("No modules selected for target %s", args.target)
        return

    engine = Engine(modules)
    context = engine.run(context)

    _save_cache(context)
    _generate_report(context, args.output)


if __name__ == "__main__":
    main()