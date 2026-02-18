"""
PII Guardian Configuration
Uses MASK strategy only
"""
import os
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field, asdict


@dataclass
class PIIConfig:
    """Configuration for PII detection and redaction"""

    # Core settings (strategy is always "mask")
    confidence_threshold: float = 0.8

    # Detection methods
    enable_regex: bool = True
    enable_ner: bool = False
    ner_model: str = "en_core_web_sm"

    # Selective redaction
    # Tier 1: Direct identifiers — always mask
    redact_types: List[str] = field(default_factory=lambda: [
        "EMAIL", "PHONE", "SSN", "CREDIT_CARD", "PASSPORT",
        "DRIVERS_LICENSE", "MEDICAL_RECORD", "IP_ADDRESS", "BANK_ACCOUNT"
    ])

    # Tier 2: Quasi-identifiers — mask only when a Tier 1 entity is present
    conditional_mask_types: List[str] = field(default_factory=lambda: [
        "PERSON", "DATE_OF_BIRTH", "ZIP_CODE", "STREET_ADDRESS"
    ])

    # Tier 2 Sensitive: High-harm attributes — mask when Tier 1 OR PERSON is present
    sensitive_mask_types: List[str] = field(default_factory=lambda: [
        "CREDIT_SCORE", "CRIMINAL_HISTORY", "EVICTION_HISTORY"
    ])

    # Audit settings
    audit_enabled: bool = True
    audit_log_path: str = "./logs/pii_audit.log"

    def __post_init__(self):
        """Validate configuration"""
        if not 0 <= self.confidence_threshold <= 1:
            raise ValueError(
                f"confidence_threshold must be between 0 and 1, got {self.confidence_threshold}"
            )

    @classmethod
    def from_env(cls) -> "PIIConfig":
        """
        Create configuration from environment variables

        Environment Variables:
            PII_CONFIDENCE_THRESHOLD: Minimum confidence for detection (default: 0.8)
            PII_ENABLE_REGEX: Enable regex detection (default: true)
            PII_ENABLE_NER: Enable NER model detection (default: false)
            PII_NER_MODEL: spaCy model name (default: en_core_web_sm)
            PII_REDACT_TYPES: Comma-separated list of entity types (default: all sensitive)
            PII_AUDIT_ENABLED: Enable audit logging (default: true)
            PII_AUDIT_LOG_PATH: Path to audit log file (default: ./logs/pii_audit.log)
        """
        # Parse redact_types
        redact_types_str = os.getenv(
            "PII_REDACT_TYPES",
            "EMAIL,PHONE,SSN,CREDIT_CARD,PASSPORT,DRIVERS_LICENSE,MEDICAL_RECORD,IP_ADDRESS,BANK_ACCOUNT"
        )
        redact_types = [t.strip() for t in redact_types_str.split(",") if t.strip()]

        conditional_mask_str = os.getenv(
            "PII_CONDITIONAL_MASK_TYPES",
            "PERSON,DATE_OF_BIRTH,ZIP_CODE,STREET_ADDRESS"
        )
        conditional_mask_types = [t.strip() for t in conditional_mask_str.split(",") if t.strip()]

        sensitive_mask_str = os.getenv(
            "PII_SENSITIVE_MASK_TYPES",
            "CREDIT_SCORE,CRIMINAL_HISTORY,EVICTION_HISTORY"
        )
        sensitive_mask_types = [t.strip() for t in sensitive_mask_str.split(",") if t.strip()]

        return cls(
            confidence_threshold=float(os.getenv("PII_CONFIDENCE_THRESHOLD", "0.8")),
            enable_regex=os.getenv("PII_ENABLE_REGEX", "true").lower() == "true",
            enable_ner=os.getenv("PII_ENABLE_NER", "false").lower() == "true",
            ner_model=os.getenv("PII_NER_MODEL", "en_core_web_sm"),
            redact_types=redact_types,
            conditional_mask_types=conditional_mask_types,
            sensitive_mask_types=sensitive_mask_types,
            audit_enabled=os.getenv("PII_AUDIT_ENABLED", "true").lower() == "true",
            audit_log_path=os.getenv("PII_AUDIT_LOG_PATH", "./logs/pii_audit.log"),
        )

    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> "PIIConfig":
        """Create configuration from dictionary"""
        # Filter out keys that aren't in the dataclass (including 'strategy')
        valid_keys = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in config_dict.items() if k in valid_keys}
        return cls(**filtered)

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary (for backward compatibility)"""
        config_dict = asdict(self)
        # Always use mask strategy
        config_dict["strategy"] = "mask"
        config_dict["enabled"] = True
        return config_dict


# Backward compatibility function
def get_pii_config() -> Dict[str, Any]:
    """
    Get PII redaction configuration from environment variables

    Returns:
        Configuration dictionary (always uses MASK strategy)
    """
    return PIIConfig.from_env().to_dict()


# Default configuration instance
DEFAULT_CONFIG = PIIConfig()
