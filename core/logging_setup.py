"""
Structured logging setup for APKStudioAI 2.1
Uses structlog for JSON logging with correlation IDs
"""
import structlog
import logging
import sys
from typing import Any, Dict


def configure_logging(
    level: str = "INFO",
    json_output: bool = False,
    include_timestamp: bool = True
) -> None:
    """Configure structlog for the application."""

    # Standard library logging setup
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, level.upper(), logging.INFO),
    )

    # Shared processors
    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]

    if include_timestamp:
        shared_processors.insert(0, structlog.processors.TimeStamper(fmt="iso"))

    if json_output:
        # JSON output for log aggregation
        structlog.configure(
            processors=shared_processors + [
                structlog.processors.JSONRenderer()
            ],
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
    else:
        # Human-readable console output
        structlog.configure(
            processors=shared_processors + [
                structlog.dev.ConsoleRenderer(colors=True)
            ],
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )


def get_logger(name: str = None) -> structlog.stdlib.BoundLogger:
    """Get a structured logger instance."""
    return structlog.get_logger(name)


class ScanContext:
    """Context manager for scan-scoped logging with correlation IDs."""

    def __init__(self, scan_id: str, apk_path: str = None):
        self.scan_id = scan_id
        self.apk_path = apk_path
        self.logger = get_logger("scan")

    def __enter__(self):
        structlog.contextvars.bind_contextvars(
            scan_id=self.scan_id,
            apk_path=self.apk_path
        )
        self.logger.info("scan_started", scan_id=self.scan_id, apk_path=self.apk_path)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self.logger.error("scan_failed", scan_id=self.scan_id, error=str(exc_val))
        else:
            self.logger.info("scan_completed", scan_id=self.scan_id)
        structlog.contextvars.clear_contextvars()


# Pre-configured loggers for different modules
loggers = {
    "archive": get_logger("archive"),
    "manifest": get_logger("manifest"),
    "dex": get_logger("dex"),
    "jadx": get_logger("jadx"),
    "apktool": get_logger("apktool"),
    "native": get_logger("native"),
    "jni": get_logger("jni"),
    "strings": get_logger("strings"),
    "permissions": get_logger("permissions"),
    "behavior": get_logger("behavior"),
    "network": get_logger("network"),
    "malware": get_logger("malware"),
    "risk": get_logger("risk"),
    "ai": get_logger("ai"),
    "androguard": get_logger("androguard"),
    "apkid": get_logger("apkid"),
    "cache": get_logger("cache"),
    "scanner": get_logger("scanner"),
    "gui": get_logger("gui"),
}


def get_module_logger(module: str) -> structlog.stdlib.BoundLogger:
    """Get a logger for a specific module."""
    return loggers.get(module, get_logger(module))