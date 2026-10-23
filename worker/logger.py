#!/usr/bin/env python3
"""
Centralized Logging Library for CodeMender & Wiz Autonomous Security Worker:
- Unified formatting with timestamps, levels, and logger names
- Visual hierarchy helpers (headers, step dividers, status emojis)
- GitHub Actions workflow command integration (::group::, ::error::, ::warning::)
- Context managers for collapsible log groups
- CLI interface for shell scripts (entrypoint.sh)
"""

import contextlib
import logging
import os
import subprocess
import sys
from typing import Any, Iterator, Optional

# Default log format with timestamps and component name
DEFAULT_LOG_FORMAT = "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
DEFAULT_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Status emoji prefixes
ICONS = {
    "HEADER": "🛡️",
    "STEP": "🔍",
    "SUCCESS": "✅",
    "INFO": "ℹ️",
    "WARN": "⚠️",
    "ERROR": "❌",
    "DEBUG": "🔬",
    "ROCKET": "🚀",
    "WRENCH": "🛠️",
    "PACKAGE": "📦",
    "TEST": "🧪",
}

_configured = False


def configure_logging(default_level: Optional[str] = None) -> None:
    """Configures root logging with standard format and level from env or default."""
    global _configured
    root = logging.getLogger()

    if default_level:
        level = getattr(logging, default_level.upper(), logging.INFO)
        root.setLevel(level)
    elif os.environ.get("ADDITIONAL_LOGGING") == "true":
        root.setLevel(logging.DEBUG)
    elif "LOG_LEVEL" in os.environ:
        level = getattr(logging, os.environ["LOG_LEVEL"].upper(), logging.INFO)
        root.setLevel(level)
    elif not _configured and root.level == logging.NOTSET:
        root.setLevel(logging.INFO)

    for h in root.handlers:
        h.setLevel(root.level)

    if not root.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setLevel(root.level)
        formatter = logging.Formatter(fmt=DEFAULT_LOG_FORMAT, datefmt=DEFAULT_DATE_FORMAT)
        handler.setFormatter(formatter)
        root.addHandler(handler)
        _configured = True


def get_logger(name: str = "codemender", level: Optional[str] = None) -> logging.Logger:
    """Returns a configured logger instance with the given component name."""
    configure_logging(level)
    log = logging.getLogger(name)
    if level:
        lvl = getattr(logging, level.upper(), logging.INFO)
        log.setLevel(lvl)
    return log


def get_codemender_version() -> str:
    """Retrieves CodeMender CLI version from 'cm --version' or environment."""
    env_ver = os.environ.get("CODEMENDER_VERSION") or os.environ.get("CM_VERSION")
    if env_ver:
        return env_ver.strip()

    try:
        res = subprocess.run(["cm", "--version"], capture_output=True, text=True, timeout=5)
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip().splitlines()[0]
    except Exception:
        pass
    return "unknown"


def log_version(logger: Optional[logging.Logger] = None) -> str:
    """Logs the installed CodeMender version with a package icon."""
    ver = get_codemender_version()
    log = logger or get_logger("codemender")
    log.info(f"{ICONS['PACKAGE']} CodeMender Version: {ver}")
    return ver


def is_github_actions() -> bool:
    """Returns True if executing inside GitHub Actions CI/CD."""
    return os.environ.get("GITHUB_ACTIONS") == "true"


# ==============================================================================
# GitHub Actions Workflow Commands
# ==============================================================================
def gha_group(title: str) -> None:
    """Emits GitHub Actions group start if in GHA environment, or prints title."""
    if is_github_actions():
        print(f"::group::{title}", flush=True)


def gha_endgroup() -> None:
    """Emits GitHub Actions group end if in GHA environment."""
    if is_github_actions():
        print("::endgroup::", flush=True)


def gha_error(message: str, file: Optional[str] = None, line: Optional[int] = None) -> None:
    """Emits GitHub Actions error annotation."""
    loc_args = []
    if file:
        loc_args.append(f"file={file}")
    if line:
        loc_args.append(f"line={line}")
    prefix = f"::error {','.join(loc_args)}::" if loc_args else "::error::"
    print(f"{prefix}{message}", flush=True)


def gha_warning(message: str, file: Optional[str] = None, line: Optional[int] = None) -> None:
    """Emits GitHub Actions warning annotation."""
    loc_args = []
    if file:
        loc_args.append(f"file={file}")
    if line:
        loc_args.append(f"line={line}")
    prefix = f"::warning {','.join(loc_args)}::" if loc_args else "::warning::"
    print(f"{prefix}{message}", flush=True)


def gha_notice(message: str, file: Optional[str] = None, line: Optional[int] = None) -> None:
    """Emits GitHub Actions notice annotation."""
    loc_args = []
    if file:
        loc_args.append(f"file={file}")
    if line:
        loc_args.append(f"line={line}")
    prefix = f"::notice {','.join(loc_args)}::" if loc_args else "::notice::"
    print(f"{prefix}{message}", flush=True)


@contextlib.contextmanager
def log_group(title: str, logger: Optional[logging.Logger] = None) -> Iterator[None]:
    """Context manager for collapsible log groups in GitHub Actions and readable terminal output."""
    log = logger or get_logger("codemender")
    log_header(title, char="-", logger=log)
    gha_group(title)
    try:
        yield
    finally:
        gha_endgroup()


# ==============================================================================
# Visual Hierarchy & Logging Helpers
# ==============================================================================
def log_header(
    title: str,
    char: str = "=",
    width: int = 80,
    logger: Optional[logging.Logger] = None,
) -> None:
    """Logs a prominent horizontal header banner."""
    sep = char * width
    log = logger or get_logger("codemender")
    log.info(sep)
    log.info(title)
    log.info(sep)


def log_step(
    step_name: str,
    step_num: Optional[int] = None,
    total_steps: Optional[int] = None,
    logger: Optional[logging.Logger] = None,
) -> None:
    """Logs a visual step divider."""
    log = logger or get_logger("codemender")
    prefix = f"Step {step_num}/{total_steps}: " if step_num and total_steps else f"Step {step_num}: " if step_num else ""
    sep = "-" * 80
    log.info(sep)
    log.info(f"{ICONS['STEP']} {prefix}{step_name}")
    log.info(sep)


def log_info(msg: str, logger: Optional[logging.Logger] = None, prefix: str = ICONS["INFO"]) -> None:
    """Logs an informational message with an optional emoji prefix."""
    log = logger or get_logger("codemender")
    p = f"{prefix} " if prefix else ""
    log.info(f"{p}{msg}")


def log_success(msg: str, logger: Optional[logging.Logger] = None) -> None:
    """Logs a success message with green check emoji."""
    log = logger or get_logger("codemender")
    log.info(f"{ICONS['SUCCESS']} {msg}")


def log_warn(msg: str, logger: Optional[logging.Logger] = None) -> None:
    """Logs a warning message with warning emoji."""
    log = logger or get_logger("codemender")
    log.warning(f"{ICONS['WARN']} {msg}")


def log_error(msg: str, logger: Optional[logging.Logger] = None) -> None:
    """Logs an error message with error emoji."""
    log = logger or get_logger("codemender")
    log.error(f"{ICONS['ERROR']} {msg}")


def log_debug(msg: str, logger: Optional[logging.Logger] = None) -> None:
    """Logs a debug message with debug emoji."""
    log = logger or get_logger("codemender")
    log.debug(f"{ICONS['DEBUG']} {msg}")
