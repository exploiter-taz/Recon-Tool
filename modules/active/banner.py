"""Banner grabbing module — protocol-aware service fingerprinting."""

import logging
import socket
import ssl
from typing import Any

from core.context import Context
from modules.base import BaseReconModule

logger = logging.getLogger(__name__)


class BannerGrabModule(BaseReconModule):
    """Grab service banners from open ports discovered by PortScanModule.

    Populates *context.banners* with a list of dicts.
    """

    TIMEOUT = 5
    RECV_SIZE = 4096

    @property
    def name(self) -> str:
        return "banner_grab"

    @property
    def description(self) -> str:
        return "Grab service banners from discovered open ports"

    def validate(self, context: Context) -> bool:
        """Need open_ports from a previous port scan."""
        if context.open_ports is None:
            logger.warning("BannerGrabModule: no open_ports in context")
            return False
        if not context.open_ports:
            logger.info("BannerGrabModule: open_ports is empty, nothing to grab")
            return False
        return True

    def run(self, context: Context) -> None:
        """Grab banners for every port in context.open_ports."""
        target_ip = context.data.get("resolved_ip", context.target)
        banners = []

        for port in context.open_ports:
            banner_data = self._grab_banner(target_ip, port)
            banners.append(banner_data)
            # FIX: Handle None banner safely
            banner_preview = banner_data.get("banner")
            if banner_preview:
                banner_preview = banner_preview[:80].replace("\n", " ")
            else:
                banner_preview = "N/A"
            logger.debug("BannerGrabModule: port %d -> %s", port, banner_preview)

        context.banners = banners
        logger.info("BannerGrabModule: grabbed %d banners", len(banners))

    def _grab_banner(self, host: str, port: int) -> dict[str, Any]:
        """Return a structured banner dict for a single port."""
        result = {
            "port": port,
            "protocol": "tcp",
            "banner": None,
            "method": None,
            "error": None,
        }

        probe = self._get_probe(port)
        method = self._get_method(port)

        # Try plain socket first, then fall back to TLS if response is empty
        for use_tls in (False, True):
            if use_tls and result.get("banner"):
                break
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.TIMEOUT)
                sock.connect((host, port))

                if port in {443, 8443} or use_tls:
                    try:
                        ctx = ssl.create_default_context()
                        sock = ctx.wrap_socket(sock, server_hostname=host)
                    except ssl.SSLError as exc:
                        if use_tls:
                            result["error"] = f"TLS failed: {exc}"
                        sock.close()
                        continue

                if probe:
                    sock.sendall(probe)

                response = sock.recv(self.RECV_SIZE)
                sock.close()

                decoded = response.decode("utf-8", errors="replace").strip()
                if decoded:
                    result["banner"] = decoded
                    result["method"] = method + (" (TLS)" if use_tls else "")
                    result["error"] = None
                elif not use_tls:
                    continue  # Try TLS
                else:
                    result["error"] = "Empty response"

            except socket.timeout:
                if use_tls:
                    result["error"] = result.get("error") or "Timeout"
            except ConnectionRefusedError:
                result["error"] = "Connection refused"
                break
            except OSError as exc:
                if use_tls:
                    result["error"] = str(exc)

        return result

    def _get_probe(self, port: int) -> bytes | None:
        """Return probe bytes, or None if server sends banner first."""
        probes = {
            21: None,
            22: None,
            23: None,
            25: b"EHLO recon\r\n",
            80: b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n",
            110: b"USER test\r\n",
            143: b"a001 CAPABILITY\r\n",
            443: b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n",
            445: None,
            3306: None,
            3389: None,
            5432: None,
            5900: None,
            8080: b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n",
            8443: b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n",
        }
        return probes.get(port, b"\r\n")

    def _get_method(self, port: int) -> str:
        """Human-readable method name."""
        methods = {
            21: "passive",
            22: "passive",
            23: "passive",
            25: "SMTP EHLO",
            80: "HTTP HEAD",
            110: "POP3 USER",
            143: "IMAP CAPABILITY",
            443: "HTTPS HEAD",
            445: "skipped",
            3306: "passive",
            3389: "passive",
            5432: "passive",
            5900: "passive",
            8080: "HTTP HEAD",
            8443: "HTTPS HEAD",
        }
        return methods.get(port, "raw newline")
