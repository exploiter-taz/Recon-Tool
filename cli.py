"""Command-line argument parsing for the recon tool."""

import argparse


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments and return a namespace object.

    Args:
        argv: Optional argument list (defaults to ``sys.argv``).

    Returns:
        Parsed arguments as a namespace.
    """
    parser = argparse.ArgumentParser(
        description="Reconnaissance tool for security assessments.",
    )

    parser.add_argument("target", help="Target domain or IP address.")

    parser.add_argument("--whois", action="store_true", help="Perform WHOIS lookup.")
    parser.add_argument("--dns", action="store_true", help="Perform DNS enumeration.")
    parser.add_argument(
        "--subdomains",
        action="store_true",
        help="Enumerate subdomains.",
    )
    parser.add_argument(
        "--ports",
        action="store_true",
        help="Scan open ports.",
    )
    parser.add_argument(
        "--banner",
        action="store_true",
        help="Grab service banners from open ports.",
    )
    parser.add_argument(
        "--tech",
        action="store_true",
        help="Detect web technologies.",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        dest="all_modules",
        help="Enable every available module.",
    )

    parser.add_argument(
        "--output",
        choices=["html", "text"],
        default="text",
        help="Output format (default: text).",
    )

    return parser.parse_args(argv)
