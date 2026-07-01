"""Shared context object passed through all recon modules."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Context:
    """Shared state container for the recon pipeline.

    Populated incrementally as each module runs.  The free-form
    *data* dictionary allows arbitrary extension without changing
    this class.
    """

    target: str
    whois: dict[str, Any] | None = None
    dns: dict[str, Any] | None = None
    subdomains: list[str] | None = None
    open_ports: list[int] | None = None
    banners: list[dict[str, Any]] | None = None
    technologies: list[dict[str, Any]] | None = None
    data: dict[str, Any] = field(default_factory=dict)
