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

        # If target is a domain, make sure we can resolve it (or that DNS
        # module already did).  We do a quick resolution here as a
        # fallback so the module is self-contained.
        try:
            socket.inet_aton(context.target)
        except OSError:
            # Not an IP — try to resolve
            try:
                resolved = socket.gethostbyname(context.target)
                # Store resolved IP in context.data so other modules can reuse it
                context.data["resolved_ip"] = resolved
                logger.info("PortScanModule: resolved %s -> %s", context.target, resolved)
            except socket.gaierror as exc:
                logger.error("PortScanModule: cannot resolve %s — %s", context.target, exc)
                return False

        return True

    def run(self, context: Context) -> None:
        """Execute Nmap port scan and write results to context."""
        target_ip = context.data.get("resolved_ip", context.target)
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