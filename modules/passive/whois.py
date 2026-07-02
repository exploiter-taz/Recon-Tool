"""WHOIS lookup module for passive reconnaissance."""

import logging
import socket
from typing import Any

import whois

from core.context import Context
from modules.base import BaseReconModule

logger = logging.getLogger(__name__)


class WhoisModule(BaseReconModule):
    """Retrieve WHOIS registration data for the target domain.

    Gathers registrar, dates, name servers, registrant details, and
    domain status without making any direct connection to the target
    infrastructure itself.
    """

    @property
    def name(self) -> str:
        return "whois"

    @property
    def description(self) -> str:
        return "Perform a WHOIS lookup against the target domain."

    def validate(self, context: Context) -> bool:
        """Check that the target looks like a valid domain name.

        Args:
            context: Shared state container for the recon pipeline.

        Returns:
            True if the target is non-empty and contains a dot.
        """
        return bool(context.target) and "." in context.target

    def run(self, context: Context) -> None:
        """Execute the WHOIS lookup and populate ``context.whois``.

        Args:
            context: Shared state container that receives WHOIS results.
        """
        logger.info("Starting WHOIS lookup for %s", context.target)

        try:
            raw = whois.whois(context.target)
        except whois.parser.WhoisDomainNotFoundError:
            logger.warning("WHOIS query failed for %s — domain may not exist", context.target)
            context.whois = None
            return
        except (socket.timeout, TimeoutError):
            logger.warning("WHOIS server timed out for %s", context.target)
            context.whois = None
            return
        except (ConnectionError, OSError):
            logger.warning("WHOIS server unreachable for %s", context.target)
            context.whois = None
            return

        context.whois = self._parse(raw)
        logger.info("WHOIS data collected for %s", context.target)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalise(value: Any) -> Any:
        """Flatten single-element lists and stringify dates."""
        if isinstance(value, list):
            # Deduplicate while preserving order.
            seen: set[str] = set()
            unique: list[str] = []
            for item in value:
                text = str(item)
                if text not in seen:
                    seen.add(text)
                    unique.append(text)
            return unique if len(unique) != 1 else unique[0]
        if hasattr(value, "isoformat"):
            return value.isoformat()
        return value

    def _parse(self, raw: whois.WhoisEntry) -> dict[str, Any]:
        """Extract the most useful fields from the raw WHOIS response.

        Args:
            raw: The parsed WHOIS entry returned by python-whois.

        Returns:
            A serialisable dictionary of WHOIS data.
        """
        fields = [
            "domain_name",
            "registrar",
            "whois_server",
            "creation_date",
            "expiration_date",
            "updated_date",
            "name_servers",
            "status",
            "emails",
            "org",
            "country",
            "state",
            "city",
            "address",
            "dnssec",
        ]
        result: dict[str, Any] = {}
        for key in fields:
            value = raw.get(key)
            if value is not None:
                result[key] = self._normalise(value)
        return result
