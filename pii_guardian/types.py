"""
Type definitions for PII Guardian
"""
from dataclasses import dataclass
from typing import List, Dict, Any


@dataclass
class PIIEntity:
    """Detected PII entity"""
    entity_type: str      # e.g., "PERSON", "SSN", "EMAIL"
    text: str             # The actual PII text
    start: int            # Start position in text
    end: int              # End position in text
    confidence: float     # Detection confidence (0-1)
    detection_method: str # "regex", "ner", "custom"


@dataclass
class ProtectionResult:
    """Result of PII protection operation"""
    text: str                           # Redacted text
    pii_count: int                      # Number of PII entities found
    entities: List[PIIEntity]           # Detected PII entities
    redaction_map: Dict[str, str]       # Original → redacted mapping
    audit_log: List[Dict[str, Any]]     # Detailed audit entries

    @property
    def is_safe(self) -> bool:
        """Check if text is safe (no PII detected)"""
        return self.pii_count == 0

    @property
    def has_pii(self) -> bool:
        """Check if text contains PII"""
        return self.pii_count > 0
