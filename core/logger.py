"""Central logging configuration for console and file output."""

import logging
import sys
from pathlib import Path


_LOG_FORMAT = "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logger(
    level: int = logging.INFO,
    log_dir: str | Path = "logs",
    log_file: str = "recon-tool.log",
) -> None:
    """Configure the root logger with console and file handlers.

    Every module and component that calls ``logging.getLogger(__name__)``
    will propagate messages to the root logger and therefore share this
    configuration.

    Args:
        level: Minimum logging level (e.g. ``logging.DEBUG``).
        log_dir: Directory where log files are written.
        log_file: Name of the log file inside *log_dir*.
    """
    root = logging.getLogger()
    root.setLevel(level)

    # Avoid duplicating handlers on repeated calls
    if root.handlers:
        return

    formatter = logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT)

    # --- Console handler (stderr) ---
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(level)
    console.setFormatter(formatter)
    root.addHandler(console)

    # --- File handler ---
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(
        log_path / log_file,
        encoding="utf-8",
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)
