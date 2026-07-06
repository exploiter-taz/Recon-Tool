"""Technology fingerprinting module.

Built and tested for Kali Linux, where WhatWeb ships by default.

Detects web server, CMS, frameworks, libraries, analytics, and CDN
technologies for a target using three layers, in order of preference:

1. WhatWeb (Ruby tool, invoked via subprocess) -- the primary detection
   source on Kali. If somehow missing (e.g. a minimal install), logs a
   clear warning with the fix (``sudo apt install whatweb``) and the
   module continues using the remaining layers.
2. python-Wappalyzer (local, offline, no API key required).
3. A lightweight pure-Python fallback that inspects HTTP response
   headers and page content directly via ``requests`` -- a safety net
   so the module still produces useful output even in the edge case
   where WhatWeb is unavailable.

Depends on ``context.open_ports`` / ``context.banners`` if the active
recon modules (portscan, banner) have already populated them -- used
only to decide which scheme (http/https) and port to target. Falls back
to scanning the raw target on port 443/80 if that data isn't present.
"""

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from typing import Any

import requests

from core.context import Context
from modules.base import BaseReconModule

logger = logging.getLogger(__name__)

_TIMEOUT_SECONDS = 10
_WHATWEB_TIMEOUT_SECONDS = 30

_SERVER_HEADER = "Server"
_POWERED_BY_HEADER = "X-Powered-By"

_CMS_BODY_SIGNATURES: dict[str, str] = {
    "WordPress": r"wp-content|wp-includes",
    "Joomla": r"/media/jui/|Joomla!",
    "Drupal": r"Drupal\.settings|sites/all/modules",
    "Shopify": r"cdn\.shopify\.com",
    "Magento": r"Mage\.Cookies|/skin/frontend/",
}

_CDN_HEADER_SIGNATURES: dict[str, str] = {
    "Cloudflare": r"cloudflare",
    "Akamai": r"akamai",
    "Fastly": r"fastly",
    "Amazon CloudFront": r"cloudfront",
}

_ANALYTICS_BODY_SIGNATURES: dict[str, str] = {
    "Google Analytics": r"google-analytics\.com|gtag\(",
    "Google Tag Manager": r"googletagmanager\.com",
    "Facebook Pixel": r"connect\.facebook\.net",
    "Hotjar": r"static\.hotjar\.com",
}


class TechDetectModule(BaseReconModule):
    """Fingerprint web technologies running on the target.

    Writes a list of detection results into ``context.technologies``.
    Each result is a dict of the form::

        {
            "source": "whatweb" | "wappalyzer" | "fallback",
            "server": str | None,
            "cms": list[str],
            "frameworks": list[str],
            "libraries": list[str],
            "analytics": list[str],
            "cdn": list[str],
            "raw": Any,  # original tool output, kept for the report layer
        }
    """

    @property
    def name(self) -> str:
        return "techdetect"

    @property
    def description(self) -> str:
        return (
            "Detect web technologies, CMS, frameworks, and server "
            "software running on the target."
        )

    def validate(self, context: Context) -> bool:
        # Side-effect-free: only confirm we have something to scan.
        return bool(context.target)

    def run(self, context: Context) -> None:
        results: list[dict[str, Any]] = []
        base_url = self._resolve_base_url(context)

        whatweb_result = self._run_whatweb(context.target)
        if whatweb_result is not None:
            results.append(whatweb_result)

        wappalyzer_result = self._run_wappalyzer(base_url)
        if wappalyzer_result is not None:
            results.append(wappalyzer_result)

        # Always run the fallback too -- it's cheap, offline, and gives a
        # sanity-check result even when the tools above succeed.
        fallback_result = self._run_fallback(base_url)
        if fallback_result is not None:
            results.append(fallback_result)

        context.technologies = results or None

        if results:
            logger.info(
                "Technology detection completed for %s (%d source(s))",
                context.target,
                len(results),
            )
        else:
            logger.warning(
                "Technology detection produced no results for %s",
                context.target,
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _resolve_base_url(self, context: Context) -> str:
        """Build a scheme-qualified URL from context, defaulting to https."""
        target = context.target
        if target.startswith("http://") or target.startswith("https://"):
            return target

        open_ports = context.open_ports or []
        if 443 in open_ports:
            return f"https://{target}"
        if 80 in open_ports:
            return f"http://{target}"
        # No port info available yet -- assume https, the common case.
        return f"https://{target}"

    def _run_whatweb(self, target: str) -> dict[str, Any] | None:
        """Run WhatWeb via subprocess, if it's installed on the host."""
        if shutil.which("whatweb") is None:
            logger.warning(
                "WhatWeb not found on PATH for %s. WhatWeb ships by default "
                "on Kali -- if missing, run: sudo apt install whatweb",
                target,
            )
            return None

        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False
            ) as tmp_file:
                tmp_path = tmp_file.name

            subprocess.run(
                [
                    "whatweb",
                    f"--log-json={tmp_path}",
                    "--quiet",
                    "--no-errors",
                    target,
                ],
                capture_output=True,
                text=True,
                timeout=_WHATWEB_TIMEOUT_SECONDS,
                check=True,
            )
            with open(tmp_path, "r") as result_file:
                content = result_file.read()
            raw = json.loads(content) if content.strip() else []
        except subprocess.TimeoutExpired:
            logger.warning("WhatWeb timed out for %s", target)
            return None
        except (subprocess.SubprocessError, json.JSONDecodeError, OSError):
            logger.warning("WhatWeb failed or returned invalid data for %s", target)
            return None
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)

        plugins = raw[-1].get("plugins", {}) if raw else {}
        detected_cms = [
            name for name in _CMS_BODY_SIGNATURES if name.replace(" ", "") in plugins
        ]
        return {
            "source": "whatweb",
            "server": self._first_string(plugins.get("HTTPServer")),
            "cms": detected_cms,
            "frameworks": [],
            "libraries": [],
            "analytics": [],
            "cdn": [],
            "raw": raw,
        }

    def _run_wappalyzer(self, base_url: str) -> dict[str, Any] | None:
        """Run local, offline Wappalyzer detection -- no API key required."""
        try:
            from Wappalyzer import Wappalyzer, WebPage
        except ImportError:
            logger.info("python-Wappalyzer not installed, skipping")
            return None

        try:
            wappalyzer = Wappalyzer.latest()
            webpage = WebPage.new_from_url(base_url, timeout=_TIMEOUT_SECONDS)
            detected = wappalyzer.analyze_with_categories(webpage)
        except Exception:
            logger.warning("Wappalyzer detection failed for %s", base_url)
            return None

        cms, frameworks, libraries, analytics, cdn = [], [], [], [], []
        for tech_name, info in detected.items():
            categories = [c.lower() for c in info.get("categories", [])]
            if "cms" in categories:
                cms.append(tech_name)
            elif "javascript frameworks" in categories or "web frameworks" in categories:
                frameworks.append(tech_name)
            elif "javascript libraries" in categories:
                libraries.append(tech_name)
            elif "analytics" in categories:
                analytics.append(tech_name)
            elif "cdn" in categories:
                cdn.append(tech_name)

        return {
            "source": "wappalyzer",
            "server": None,
            "cms": cms,
            "frameworks": frameworks,
            "libraries": libraries,
            "analytics": analytics,
            "cdn": cdn,
            "raw": detected,
        }

    def _run_fallback(self, base_url: str) -> dict[str, Any] | None:
        """Pure-Python fallback: inspect headers and body with requests."""
        try:
            response = requests.get(
                base_url, timeout=_TIMEOUT_SECONDS, allow_redirects=True
            )
        except requests.RequestException:
            logger.warning("Fallback HTTP request failed for %s", base_url)
            return None

        headers = response.headers
        body = response.text

        server = headers.get(_SERVER_HEADER)
        powered_by = headers.get(_POWERED_BY_HEADER)

        cms = [
            name
            for name, pattern in _CMS_BODY_SIGNATURES.items()
            if re.search(pattern, body, re.IGNORECASE)
        ]
        cdn = [
            name
            for name, pattern in _CDN_HEADER_SIGNATURES.items()
            if re.search(pattern, str(headers), re.IGNORECASE)
        ]
        analytics = [
            name
            for name, pattern in _ANALYTICS_BODY_SIGNATURES.items()
            if re.search(pattern, body, re.IGNORECASE)
        ]

        return {
            "source": "fallback",
            "server": server,
            "cms": cms,
            "frameworks": [powered_by] if powered_by else [],
            "libraries": [],
            "analytics": analytics,
            "cdn": cdn,
            "raw": {"status_code": response.status_code},
        }

    @staticmethod
    def _first_string(value: Any) -> str | None:
        """WhatWeb plugin values look like {"string": ["nginx"], ...}."""
        if isinstance(value, dict):
            strings = value.get("string")
            if isinstance(strings, list) and strings:
                return str(strings[0])
        if isinstance(value, str):
            return value
        return None