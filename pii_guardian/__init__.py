"""
PII Guardian - Reusable PII Detection and Redaction Library

A standalone library for detecting and redacting personally identifiable
information (PII) from text. Use it anywhere in your project: RAG pipelines,
data preprocessing, API filtering, logging, and more.

Quick Start:
    >>> from pii_guardian import PIIGuardian
    >>>
    >>> guardian = PIIGuardian()
    >>> result = guardian.protect("Email: john@example.com")
    >>> print(result.text)
    Email: [EMAIL]
    >>> print(result.is_safe)
    False

Features:
    - Multi-layer detection (Regex + NER + Custom Rules)
    - Multiple redaction strategies (mask, remove, hash, partial)
    - Selective redaction by entity type
    - RAG pipeline integration (protect_chunks method)
    - Configurable via constructor, config object, or environment variables

For more information, see README.md
"""

__version__ = "1.0.0"
__author__ = "PII Guardian Team"

# Main facade
from pii_guardian.guardian import PIIGuardian

# Configuration
from pii_guardian.config import PIIConfig, get_pii_config

# Detection & Redaction (for advanced use)
from pii_guardian.detector import PIIDetector, get_pii_detector
from pii_guardian.redactor import PIIRedactor, get_pii_redactor

# Types
from pii_guardian.types import (
    PIIEntity,
    ProtectionResult,
)

# Exceptions
from pii_guardian.exceptions import (
    PIIGuardianError,
    ConfigurationError,
    DetectionError,
    RedactionError,
)

# Public API
__all__ = [
    # Main API
    "PIIGuardian",
    # Configuration
    "PIIConfig",
    "get_pii_config",
    # Advanced components
    "PIIDetector",
    "PIIRedactor",
    "get_pii_detector",
    "get_pii_redactor",
    # Types
    "PIIEntity",
    "ProtectionResult",
    # Exceptions
    "PIIGuardianError",
    "ConfigurationError",
    "DetectionError",
    "RedactionError",
]
