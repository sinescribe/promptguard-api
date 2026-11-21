"""PromptGuard API package."""

from .app import (
    DELIMITER_ANOMALIES,
    INJECTION_PATTERNS,
    VALID_API_KEYS,
    BatchScanRequest,
    ScanRequest,
    ScanResponse,
    analyze_prompt,
    app,
    main,
    verify_gumroad_license,
)

__version__ = "0.1.1"

__all__ = [
    "__version__",
    "app",
    "analyze_prompt",
    "verify_gumroad_license",
    "main",
    "ScanRequest",
    "ScanResponse",
    "BatchScanRequest",
    "INJECTION_PATTERNS",
    "DELIMITER_ANOMALIES",
    "VALID_API_KEYS",
]
