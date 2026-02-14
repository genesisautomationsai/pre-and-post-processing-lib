"""
Exception hierarchy for PII Guardian
"""


class PIIGuardianError(Exception):
    """Base exception for PII Guardian errors"""
    pass


class ConfigurationError(PIIGuardianError):
    """Raised when configuration is invalid"""
    pass


class DetectionError(PIIGuardianError):
    """Raised when PII detection fails"""
    pass


class RedactionError(PIIGuardianError):
    """Raised when PII redaction fails"""
    pass
