"""Passive subdomain enumeration module."""

import logging
from typing import Any

import requests

from core.context import Context
from modules.base import BaseReconModule

logger = logging.getLogger(__name__)

# Timeout (seconds) for HTTP requests to public data sources.
_HTTP_TIMEOUT: int = 30


class SubdomainsModule(BaseReconModule):
    """Discover subdomains using passive, public data sources.

    Queries Certificate Transparency logs (crt.sh) and other public
    APIs to enumerate subdomains without sending any traffic directly
    to the target infrastructure.
    """

    @property
    def name(self) -> str:
        return "subdomains"

    @property
    def description(self) -> str:
        return "Enumerate subdomains passively via public data sources."

    def validate(self, context: Context) -> bool:
        """Check that the target looks like a valid domain name.

        Args:
            context: Shared state container for the recon pipeline.

        Returns:
            True if the target is non-empty and contains a dot.
        """
        return bool(context.target) and "." in context.target

    def run(self, context: Context) -> None:
        """Collect subdomains from public sources and populate ``context.subdomains``.

        Args:
            context: Shared state container that receives subdomain results.
        """
        logger.info("Starting passive subdomain enumeration for %s", context.target)

        discovered: set[str] = set()

        # --- Source 1: Certificate Transparency (crt.sh) ---
        crtsh = self._query_crtsh(context.target)
        discovered.update(crtsh)
        logger.info(
            "crt.sh returned %d unique subdomain(s) for %s",
            len(crtsh),
            context.target,
        )

        # --- Source 2: Hackertarget API ---
        ht = self._query_hackertarget(context.target)
        discovered.update(ht)
        logger.info(
            "HackerTarget returned %d unique subdomain(s) for %s",
            len(ht),
            context.target,
        )

        # Normalise and sort the final list.
        cleaned = sorted(self._clean(discovered, context.target))
        context.subdomains = cleaned if cleaned else None

        logger.info(
            "Passive subdomain enumeration completed — %d total unique subdomain(s)",
            len(cleaned),
        )

    # ------------------------------------------------------------------
    # Data-source helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _query_crtsh(target: str) -> set[str]:
        """Query crt.sh Certificate Transparency logs.

        Args:
            target: The root domain to search for.

        Returns:
            A set of discovered subdomain strings.
        """
        url = "https://crt.sh/"
        params: dict[str, str] = {"q": f"%.{target}", "output": "json"}
        results: set[str] = set()

        try:
            response = requests.get(url, params=params, timeout=_HTTP_TIMEOUT)
            response.raise_for_status()
            entries: list[dict[str, Any]] = response.json()
        except requests.exceptions.Timeout:
            logger.warning("crt.sh request timed out for %s", target)
            return results
        except requests.exceptions.ConnectionError:
            logger.warning("Could not connect to crt.sh for %s", target)
            return results
        except (requests.exceptions.HTTPError, ValueError):
            logger.warning("crt.sh returned an invalid response for %s", target)
            return results

        for entry in entries:
            name_value = entry.get("name_value", "")
            # A single entry can list multiple domains separated by newlines.
            for name in name_value.splitlines():
                name = name.strip().lower()
                # Skip wildcard prefixes.
                if name.startswith("*."):
                    name = name[2:]
                if name:
                    results.add(name)

        return results

    @staticmethod
    def _query_hackertarget(target: str) -> set[str]:
        """Query the HackerTarget free host search API.

        Args:
            target: The root domain to search for.

        Returns:
            A set of discovered subdomain strings.
        """
        url = f"https://api.hackertarget.com/hostsearch/?q={target}"
        results: set[str] = set()

        try:
            response = requests.get(url, timeout=_HTTP_TIMEOUT)
            response.raise_for_status()
            text = response.text
        except requests.exceptions.Timeout:
            logger.warning("HackerTarget request timed out for %s", target)
            return results
        except (requests.exceptions.ConnectionError, requests.exceptions.HTTPError):
            logger.warning("HackerTarget unavailable for %s", target)
            return results

        # The API returns CSV lines: "subdomain,ip"
        if "error" in text.lower() or "API count exceeded" in text:
            logger.warning("HackerTarget rate-limited or error for %s", target)
            return results

        for line in text.splitlines():
            parts = line.split(",")
            if parts:
                name = parts[0].strip().lower()
                if name and "." in name:
                    results.add(name)

        return results

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _clean(subdomains: set[str], root: str) -> list[str]:
        """Filter and normalise the raw subdomain set.

        Removes entries that do not actually belong to the root domain
        and strips trailing dots.

        Args:
            subdomains: Raw set of discovered subdomain strings.
            root: The root domain used as a suffix filter.

        Returns:
            A deduplicated, sorted list of valid subdomains.
        """
        root = root.lower().rstrip(".")
        cleaned: set[str] = set()
        for sub in subdomains:
            sub = sub.rstrip(".")
            if sub.endswith(root):
                cleaned.add(sub)
        return sorted(cleaned)
