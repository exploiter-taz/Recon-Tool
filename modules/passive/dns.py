"""DNS enumeration module for passive reconnaissance."""

import logging
from typing import Any

import dns.resolver
import dns.reversename

from core.context import Context
from modules.base import BaseReconModule

logger = logging.getLogger(__name__)

# Record types to enumerate during a standard passive DNS scan.
_RECORD_TYPES: list[str] = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME"]


class DnsModule(BaseReconModule):
    """Enumerate DNS records and resolve IP addresses for the target domain.

    Queries A, AAAA, MX, TXT, NS, SOA, and CNAME records using the
    system's configured DNS resolver.  Also performs reverse DNS lookups
    on any discovered A/AAAA addresses.  No direct sockets are opened to
    the target — all queries go through the DNS resolver.
    """

    @property
    def name(self) -> str:
        return "dns"

    @property
    def description(self) -> str:
        return "Enumerate DNS records and resolve IPs for the target domain."

    def validate(self, context: Context) -> bool:
        """Check that the target looks like a valid domain name.

        Args:
            context: Shared state container for the recon pipeline.

        Returns:
            True if the target is non-empty and contains a dot.
        """
        return bool(context.target) and "." in context.target

    def run(self, context: Context) -> None:
        """Query DNS record types and populate ``context.dns``.

        Args:
            context: Shared state container that receives DNS results.
        """
        logger.info("Starting DNS enumeration for %s", context.target)

        results: dict[str, Any] = {}

        for rtype in _RECORD_TYPES:
            records = self._query(context.target, rtype)
            if records:
                results[rtype] = records

        # Reverse DNS for discovered A / AAAA addresses.
        ip_addresses: list[str] = results.get("A", []) + results.get("AAAA", [])
        if ip_addresses:
            ptr_records = self._reverse_lookups(ip_addresses)
            if ptr_records:
                results["PTR"] = ptr_records

        context.dns = results if results else None
        logger.info(
            "DNS enumeration completed for %s — %d record type(s) found",
            context.target,
            len(results),
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _query(target: str, rtype: str) -> list[str]:
        """Resolve a single DNS record type for *target*.

        Args:
            target: The domain name to query.
            rtype: The DNS record type (e.g. ``"A"``, ``"MX"``).

        Returns:
            A list of string representations of the records, or an
            empty list if the query fails or yields no results.
        """
        try:
            answers = dns.resolver.resolve(target, rtype)
            return [rdata.to_text() for rdata in answers]
        except dns.resolver.NoAnswer:
            logger.debug("No %s records found for %s", rtype, target)
        except dns.resolver.NXDOMAIN:
            logger.warning("Domain %s does not exist (NXDOMAIN)", target)
        except dns.resolver.NoNameservers:
            logger.warning(
                "No nameservers available for %s record of %s", rtype, target
            )
        except dns.exception.Timeout:
            logger.warning(
                "DNS query timed out for %s record of %s", rtype, target
            )
        except dns.exception.DNSException:
            logger.warning(
                "DNS query error for %s record of %s", rtype, target
            )
        return []

    @staticmethod
    def _reverse_lookups(addresses: list[str]) -> dict[str, str]:
        """Perform reverse DNS (PTR) lookups on a list of IP addresses.

        Args:
            addresses: IP addresses to look up.

        Returns:
            A mapping of IP address → PTR hostname for successful lookups.
        """
        ptr_map: dict[str, str] = {}
        for addr in addresses:
            try:
                rev_name = dns.reversename.from_address(addr)
                answers = dns.resolver.resolve(rev_name, "PTR")
                ptr_map[addr] = answers[0].to_text()
            except (dns.exception.DNSException, Exception):
                logger.debug("Reverse DNS failed for %s", addr)
        return ptr_map
