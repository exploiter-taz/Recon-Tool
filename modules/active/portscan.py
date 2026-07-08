"""Port scanning module using python-nmap for fast, reliable discovery."""

import logging
import socket
from typing import Any

from core.context import Context
from modules.base import BaseReconModule

logger = logging.getLogger(__name__)


class PortScanModule(BaseReconModule):
    """Discover open TCP ports on the target using Nmap.

    Populates *context.open_ports* with a list of integers.
    """

    @property
    def name(self) -> str:
        return "port_scan"

    @property
    def description(self) -> str:
        return "Scan target for open TCP ports using Nmap"

    def validate(self, context: Context) -> bool:
        """Need a target (domain or IP) to scan."""
        if not context.target:
            logger.warning("PortScanModule: no target in context")
            return False
        return True

    def run(self, context: Context) -> None:
        """Resolve target, execute Nmap port scan, and write results to context."""
        target_ip = self._resolve_target(context)
        if target_ip is None:
            context.open_ports = []
            return
        logger.info("PortScanModule: scanning %s", target_ip)

        try:
            import nmap
        except ImportError as exc:
            logger.error("PortScanModule: python-nmap not installed — %s", exc)
            context.open_ports = []
            return

        nm = nmap.PortScanner()

        # Top 1000 ports + common extras, fast but thorough
        # -sS requires root; fall back to -sT if unprivileged
        scan_args = "-sS --top-ports 1000 --open -T4"
        try:
            nm.scan(hosts=target_ip, arguments=scan_args)
        except nmap.PortScannerError:
            # Privileged SYN scan failed — try connect scan
            logger.warning("PortScanModule: SYN scan failed, falling back to connect scan")
            scan_args = "-sT --top-ports 1000 --open -T4"
            nm.scan(hosts=target_ip, arguments=scan_args)

        open_ports: list[int] = []
        if target_ip in nm.all_hosts():
            for proto in nm[target_ip].all_protocols():
                ports = nm[target_ip][proto].keys()
                open_ports.extend(sorted(ports))

        # Deduplicate and sort
        open_ports = sorted(set(open_ports))
        context.open_ports = open_ports

        logger.info("PortScanModule: found %d open ports — %s", len(open_ports), open_ports)

    @staticmethod
    def _resolve_target(context: Context) -> str | None:
        """Resolve target domain to an IP address if needed.

        Returns the IP address, or the original target if it is already
        an IP.  Returns ``None`` if resolution fails.
        """
        target = context.target
        try:
            socket.inet_aton(target)
            return target
        except OSError:
            pass

        try:
            resolved = socket.gethostbyname(target)
            context.data["resolved_ip"] = resolved
            logger.info("PortScanModule: resolved %s -> %s", target, resolved)
            return resolved
        except socket.gaierror as exc:
            logger.error("PortScanModule: cannot resolve %s — %s", target, exc)
            return None