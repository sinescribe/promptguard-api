"""
Backward-compatible top-level entrypoint re-exporting promptguard_api.app.
"""

from promptguard_api.app import (
    API_KEY_NAME,
    DELIMITER_ANOMALIES,
    FREE_RATE_LIMIT_RPM,
    GUMROAD_PRO_URL,
    GUMROAD_PRODUCT_PERMALINK,
    GUMROAD_TOOLKITS,
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

__all__ = [
    "API_KEY_NAME",
    "DELIMITER_ANOMALIES",
    "FREE_RATE_LIMIT_RPM",
    "GUMROAD_PRO_URL",
    "GUMROAD_PRODUCT_PERMALINK",
    "GUMROAD_TOOLKITS",
    "INJECTION_PATTERNS",
    "VALID_API_KEYS",
    "BatchScanRequest",
    "ScanRequest",
    "ScanResponse",
    "analyze_prompt",
    "app",
    "main",
    "verify_gumroad_license",
]

if __name__ == "__main__":
    main()
