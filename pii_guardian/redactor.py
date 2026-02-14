"""
PII Redaction - MASK Strategy Only
Replaces PII with simple placeholders like [EMAIL], [PHONE], [SSN]
"""
from typing import List, Dict, Any
import logging
from pii_guardian.types import PIIEntity

logger = logging.getLogger(__name__)


class PIIRedactor:
    """Redact detected PII from text using MASK strategy"""

    def __init__(self):
        """Initialize redactor with MASK strategy"""
        self.strategy = "mask"

    def redact(
        self,
        text: str,
        entities: List[PIIEntity]
    ) -> Dict[str, Any]:
        """
        Redact PII from text using MASK strategy

        Args:
            text: Original text
            entities: Detected PII entities

        Returns:
            Dict with:
                - redacted_text: Text with PII masked as [TYPE]
                - redaction_map: Map of original → [TYPE]
                - audit_log: List of redactions made
                - pii_count: Number of PII entities redacted

        Example:
            Input:  "Email: john@test.com"
            Output: "Email: [EMAIL]"
        """
        return self._mask(text, entities)

    def _mask(self, text: str, entities: List[PIIEntity]) -> Dict[str, Any]:
        """Replace PII with [TYPE] placeholder"""
        redacted_text = text
        redaction_map = {}
        audit_log = []

        # Sort entities by position (reverse to maintain string positions)
        entities_sorted = sorted(entities, key=lambda e: e.start, reverse=True)

        for entity in entities_sorted:
            placeholder = f"[{entity.entity_type}]"

            # Replace in text
            redacted_text = (
                redacted_text[:entity.start] +
                placeholder +
                redacted_text[entity.end:]
            )

            # Track redaction
            redaction_map[entity.text] = placeholder
            audit_log.append({
                "type": entity.entity_type,
                "redacted": placeholder,
                "position": (entity.start, entity.end),
                "confidence": entity.confidence,
                "method": entity.detection_method
            })

        return {
            "redacted_text": redacted_text,
            "redaction_map": redaction_map,
            "audit_log": audit_log,
            "pii_count": len(entities)
        }


# Singleton instance (optional)
_redactor_instance = None


def get_pii_redactor() -> PIIRedactor:
    """Get or create PII redactor singleton"""
    global _redactor_instance
    if _redactor_instance is None:
        _redactor_instance = PIIRedactor()
    return _redactor_instance
