"""Technology detection module — fingerprint web services from banners."""

import logging
import re
from typing import Any

from core.context import Context
from modules.base import BaseReconModule

logger = logging.getLogger(__name__)


class TechDetectModule(BaseReconModule):
    """Detect web technologies, server software, and frameworks from
    banner data produced by BannerGrabModule.

    Populates *context.technologies* with a list of dicts:
        [{"port": 80, "technology": "Apache", "version": "2.4.41", "confidence": "high"}, ...]
    """

    @property
    def name(self) -> str:
        return "tech_detect"

    @property
    def description(self) -> str:
        return "Detect technologies from service banners"

    def validate(self, context: Context) -> bool:
        """Need banners to analyse."""
        if context.banners is None:
            logger.warning("TechDetectModule: no banners in context — run banner_grab first")
            return False
        if not context.banners:
            logger.info("TechDetectModule: banners list is empty, nothing to detect")
            return False
        return True

    def run(self, context: Context) -> None:
        """Analyse each banner and extract technology fingerprints."""
        technologies: list[dict[str, Any]] = []

        for banner_entry in context.banners:
            port = banner_entry["port"]
            banner = banner_entry.get("banner")
            if not banner:
                continue

            findings = self._fingerprint(port, banner)
            technologies.extend(findings)

        context.technologies = technologies
        logger.info("TechDetectModule: identified %d technology fingerprints", len(technologies))

    def _fingerprint(self, port: int, banner: str) -> list[dict[str, Any]]:
        """Return a list of technology dicts extracted from *banner*."""
        findings: list[dict[str, Any]] = []
        banner_lower = banner.lower()

        # --- Web servers ---
        if "server:" in banner_lower or port in {80, 443, 8080, 8443}:
            m = re.search(r"Server:\s*([^\r\n]+)", banner, re.IGNORECASE)
            if m:
                server = m.group(1).strip()
                findings.append(self._parse_server(server, port))

        # --- SSH ---
        if banner.startswith("SSH-"):
            m = re.match(r"SSH-2\.0-([A-Za-z0-9_+.-]+)", banner)
            if m:
                findings.append({
                    "port": port,
                    "technology": "OpenSSH",
                    "version": m.group(1),
                    "category": "remote_access",
                    "confidence": "high",
                })

        # --- FTP ---
        if "vsftpd" in banner_lower:
            m = re.search(r"vsftpd\s+([0-9.]+)", banner, re.IGNORECASE)
            findings.append({
                "port": port,
                "technology": "vsftpd",
                "version": m.group(1) if m else "unknown",
                "category": "file_transfer",
                "confidence": "high",
            })
        elif "proftpd" in banner_lower:
            m = re.search(r"ProFTPD\s+([0-9.]+)", banner, re.IGNORECASE)
            findings.append({
                "port": port,
                "technology": "ProFTPD",
                "version": m.group(1) if m else "unknown",
                "category": "file_transfer",
                "confidence": "high",
            })
        elif "ftp" in banner_lower and "220" in banner:
            findings.append({
                "port": port,
                "technology": "FTP",
                "version": "unknown",
                "category": "file_transfer",
                "confidence": "medium",
            })

        # --- SMTP ---
        if "esmtp" in banner_lower or "postfix" in banner_lower:
            m = re.search(r"Postfix\s*([0-9.]+)?", banner, re.IGNORECASE)
            findings.append({
                "port": port,
                "technology": "Postfix",
                "version": m.group(1) if m else "unknown",
                "category": "mail",
                "confidence": "high" if m else "medium",
            })

        # --- MySQL ---
        if port == 3306 and not banner.isprintable():
            # MySQL sends a binary handshake — heuristic match
            findings.append({
                "port": port,
                "technology": "MySQL",
                "version": "unknown",
                "category": "database",
                "confidence": "medium",
            })

        # --- Generic X-Powered-By / framework headers ---
        x_powered = re.search(r"X-Powered-By:\s*([^\r\n]+)", banner, re.IGNORECASE)
        if x_powered:
            findings.append({
                "port": port,
                "technology": x_powered.group(1).strip(),
                "version": "unknown",
                "category": "framework",
                "confidence": "medium",
            })

        return findings

    def _parse_server(self, server_str: str, port: int) -> dict[str, Any]:
        """Parse a Server header string like 'Apache/2.4.41 (Ubuntu)'."""
        parts = server_str.split()
        name_ver = parts[0] if parts else server_str

        if "/" in name_ver:
            name, version = name_ver.split("/", 1)
        else:
            name, version = name_ver, "unknown"

        # Clean up common names
        name = name.strip()
        category = "web_server"
        if "nginx" in name.lower():
            category = "web_server"
        elif "apache" in name.lower():
            category = "web_server"
        elif "iis" in name.lower() or "microsoft" in name.lower():
            category = "web_server"
        elif "lighttpd" in name.lower():
            category = "web_server"

        return {
            "port": port,
            "technology": name,
            "version": version,
            "category": category,
            "confidence": "high",
        }