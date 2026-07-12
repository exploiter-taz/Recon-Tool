import json
import logging
import re
import shutil
import subprocess
import warnings
from typing import Any

import requests

from core.context import Context
from modules.base import BaseReconModule

logger = logging.getLogger(__name__)

_TIMEOUT_SECONDS = 10
_WHATWEB_TIMEOUT_SECONDS = 30

# Minimal signatures for the pure-Python fallback layer. Each entry maps a
# technology name to (header_name, regex) or (None, regex_against_body).
_SERVER_HEADER = "Server"
_POWERED_BY_HEADER = "X-Powered-By"

_CMS_BODY_SIGNATURES: dict[str, str] = {
    "WordPress": r"wp-content|wp-includes",
    "Joomla": r"/media/jui/|Joomla!",
    "Drupal": r"Drupal\.settings|sites/all/modules",
    "Shopify": r"cdn\.shopify\.com",
    "Magento": r"Mage\.Cookies|/skin/frontend/",
}

# WhatWeb plugin names don't always match the keys above 1:1 (e.g. WhatWeb
# may report "WordPress", "PossibleWordPress", or version-suffixed variants).
# This maps WhatWeb plugin name patterns -> our canonical CMS name so we
# don't silently under-report CMS hits from WhatWeb's JSON output.
_WHATWEB_CMS_ALIASES: dict[str, str] = {
    "wordpress": "WordPress",
    "joomla": "Joomla",
    "drupal": "Drupal",
    "shopify": "Shopify",
    "magento": "Magento",
}

_CDN_HEADER_VALUE_SIGNATURES: dict[str, str] = {
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

# Some entries in python-Wappalyzer's bundled (and no longer updated)
# fingerprint file have malformed data -- e.g. a technology name with a
# trailing "<https://vendor.com>" URL fragment baked in, left over from a
# broken capture group in that entry's regex. Strip anything that looks
# like a trailing angle-bracket annotation so the report stays clean
# regardless of which upstream fingerprint entry produced it.
_TRAILING_URL_ANNOTATION = re.compile(r"\s*<[^>]+>\s*$")


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

    @staticmethod
    def _clean_tech_name(name: str) -> str:
        """Strip junk that stale/broken fingerprint entries sometimes leave
        in a technology name, e.g. "WordPress VIP <https://wpvip.com>" ->
        "WordPress VIP". Safe to run on already-clean names -- it's a no-op
        if there's nothing to strip.
        """
        return _TRAILING_URL_ANNOTATION.sub("", name).strip()

    def _run_whatweb(self, target: str) -> dict[str, Any] | None:
        """Run WhatWeb via subprocess, if it's installed on the host."""
        if shutil.which("whatweb") is None:
            logger.warning(
                "WhatWeb not found on PATH for %s. WhatWeb ships by default "
                "on Kali -- if missing, run: sudo apt install whatweb",
                target,
            )
            return None

        try:
            proc = subprocess.run(
                ["whatweb", "--log-json=-", "--no-errors", target],
                capture_output=True,
                text=True,
                timeout=_WHATWEB_TIMEOUT_SECONDS,
                check=True,
            )
            raw = json.loads(proc.stdout) if proc.stdout.strip() else []
        except subprocess.TimeoutExpired:
            logger.warning("WhatWeb timed out for %s", target)
            return None
        except subprocess.CalledProcessError as exc:
            # WhatWeb ran but exited non-zero -- surface its exit code and
            # any stderr it produced instead of a generic "failed" message.
            stderr = (exc.stderr or "").strip()
            logger.warning(
                "WhatWeb exited with code %s for %s%s",
                exc.returncode,
                target,
                f": {stderr}" if stderr else "",
            )
            return None
        except json.JSONDecodeError as exc:
            logger.warning(
                "WhatWeb returned invalid JSON for %s (%s)", target, exc
            )
            return None
        except subprocess.SubprocessError as exc:
            logger.warning(
                "WhatWeb subprocess error for %s (%s: %s)",
                target,
                type(exc).__name__,
                exc,
            )
            return None

        # Defensive: `raw` may be a non-empty list whose first element isn't
        # a dict (unexpected WhatWeb output shape). Don't let that crash the
        # whole module -- degrade gracefully like every other layer here.
        if raw and isinstance(raw[0], dict):
            plugins = raw[0].get("plugins", {})
        else:
            plugins = {}

        return {
            "source": "whatweb",
            "server": self._first_string(plugins.get("HTTPServer")),
            "cms": self._match_whatweb_cms(plugins),
            "frameworks": [],
            "libraries": [],
            "analytics": [],
            "cdn": [],
            "raw": raw,
        }

    def _match_whatweb_cms(self, plugins: dict[str, Any]) -> list[str]:
        """Map WhatWeb's own plugin names onto our canonical CMS names.

        WhatWeb plugin keys don't reliably match `_CMS_BODY_SIGNATURES`
        exactly (casing, suffixes like "-Version", etc.), so we do a
        case-insensitive substring match against known aliases instead of
        a strict `in` check against a different dict's keys.
        """
        detected: list[str] = []
        for plugin_key in plugins:
            key_lower = plugin_key.lower()
            for alias, canonical_name in _WHATWEB_CMS_ALIASES.items():
                if alias in key_lower and canonical_name not in detected:
                    detected.append(canonical_name)
        return detected

    def _run_wappalyzer(self, base_url: str) -> dict[str, Any] | None:
        """Run local, offline Wappalyzer detection -- no API key required."""
        try:
            from Wappalyzer import Wappalyzer, WebPage  # type: ignore[import-not-found]
        except ImportError as exc:
            # Don't assume it's simply "not installed" -- a stale dependency
            # (e.g. pkg_resources removed by setuptools>=82) raises
            # ModuleNotFoundError too, and looks identical to a missing
            # package unless we log the real exception. See project notes:
            # pin `setuptools<82` in requirements.txt if this fires.
            logger.info(
                "Wappalyzer unavailable, skipping (%s: %s)",
                type(exc).__name__,
                exc,
            )
            return None

        try:
            # python-Wappalyzer's bundled fingerprint file is an old,
            # frozen snapshot with a few malformed regex entries. Those
            # raise harmless UserWarnings on every run -- suppress just
            # this call so demo/CLI output stays readable, without hiding
            # real errors (warnings are not exceptions; those still raise).
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                wappalyzer = Wappalyzer.latest()
                webpage = WebPage.new_from_url(base_url, timeout=_TIMEOUT_SECONDS)
                detected = wappalyzer.analyze_with_categories(webpage)
        except Exception as exc:
            # Broad except is intentional here (this layer must never take
            # down the whole scan), but log the exception type/message so a
            # real bug doesn't hide behind a generic warning forever.
            logger.warning(
                "Wappalyzer detection failed for %s (%s: %s)",
                base_url,
                type(exc).__name__,
                exc,
            )
            return None

        cms, frameworks, libraries, analytics, cdn = [], [], [], [], []
        for raw_tech_name, info in detected.items():
            tech_name = self._clean_tech_name(raw_tech_name)
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

        # Only search actual header VALUES, not header names, so a header
        # literally named e.g. "X-Fastly-Debug" on a non-Fastly site can't
        # produce a false positive by matching its own name.
        cdn = [
            name
            for name, pattern in _CDN_HEADER_VALUE_SIGNATURES.items()
            if any(re.search(pattern, value, re.IGNORECASE) for value in headers.values())
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
        """WhatWeb plugin values are often lists -- grab the first string."""
        if isinstance(value, list) and value:
            first = value[0]
            if isinstance(first, dict):
                strings = first.get("string")
                if isinstance(strings, list) and strings:
                    return str(strings[0])
                return None
            return str(first)
        if isinstance(value, str):
            return value
        return None
