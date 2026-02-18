"""
PII Detection Engine
Multi-layer approach: Regex → NER → Custom Rules
"""
from typing import List, Dict, Any, Optional
import re
import logging
from pii_guardian.types import PIIEntity

logger = logging.getLogger(__name__)


class PIIDetector:
    """Multi-layer PII detection system"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize PII detector

        Args:
            config: Configuration dict with:
                - enable_regex: bool (default True)
                - enable_ner: bool (default False - requires spacy)
                - confidence_threshold: float (default 0.8)
                - ner_model: str (default "en_core_web_sm")
        """
        self.config = config or {}
        self.patterns = self._load_patterns()
        self.ner_model = None

        # Load NER model if enabled
        if self.config.get("enable_ner", False):
            try:
                self.ner_model = self._load_ner_model()
                logger.info("NER model loaded successfully")
            except Exception as e:
                logger.warning(f"Could not load NER model: {e}")
                logger.info("Falling back to regex-only detection")

    def detect_all(self, text: str) -> List[PIIEntity]:
        """
        Detect all PII in text using all enabled layers

        Args:
            text: Input text to scan

        Returns:
            List of detected PII entities (deduplicated and sorted)
        """
        entities = []

        # Layer 1: Regex patterns (fast, high precision)
        if self.config.get("enable_regex", True):
            regex_entities = self._detect_regex(text)
            entities.extend(regex_entities)
            logger.debug(f"Regex detected {len(regex_entities)} entities")

        # Layer 2: NER model (slower, high recall)
        if self.config.get("enable_ner", False) and self.ner_model:
            ner_entities = self._detect_ner(text)
            entities.extend(ner_entities)
            logger.debug(f"NER detected {len(ner_entities)} entities")

        # Layer 3: Custom rules (domain-specific)
        custom_entities = self._detect_custom(text)
        entities.extend(custom_entities)

        # Deduplicate overlapping entities (keep highest confidence)
        entities = self._deduplicate_entities(entities)

        # Filter by confidence threshold
        threshold = self.config.get("confidence_threshold", 0.8)
        entities = [e for e in entities if e.confidence >= threshold]

        # Filter by entity types (tiered redaction)
        always_mask = set(self.config.get("redact_types", []))
        conditional_mask = set(self.config.get("conditional_mask_types", []))
        # sensitive_trigger_types: their presence causes PERSON to be masked,
        # but they are never masked themselves (details stay visible)
        sensitive_triggers = set(self.config.get("sensitive_trigger_types", []))

        if conditional_mask or sensitive_triggers:
            tier1 = [e for e in entities if e.entity_type in always_mask]
            tier2 = [e for e in entities if e.entity_type in conditional_mask]

            # Tier 2 (PERSON, DOB, ZIP, etc.) is unblocked by Tier 1 OR by a sensitive trigger
            sensitive_present = any(e.entity_type in sensitive_triggers for e in entities)
            include_tier2 = bool(tier1) or sensitive_present

            # Sensitive trigger types are intentionally excluded from output (never masked)
            entities = tier1 + (tier2 if include_tier2 else [])
            logger.debug(
                f"Tiered masking: {len(tier1)} Tier-1, "
                f"{len(tier2) if include_tier2 else 0}/{len(tier2)} Tier-2 "
                f"(sensitive trigger present: {sensitive_present})"
            )
        elif always_mask:
            entities = [e for e in entities if e.entity_type in always_mask]
            logger.debug(f"Filtering to redact only: {', '.join(always_mask)}")

        logger.info(f"Total PII entities detected: {len(entities)}")
        return entities

    def _detect_regex(self, text: str) -> List[PIIEntity]:
        """Detect PII using regex patterns"""
        entities = []

        for entity_type, pattern in self.patterns.items():
            try:
                for match in re.finditer(pattern, text, re.IGNORECASE):
                    entities.append(PIIEntity(
                        entity_type=entity_type,
                        text=match.group(0),
                        start=match.start(),
                        end=match.end(),
                        confidence=0.95,  # High confidence for regex matches
                        detection_method="regex"
                    ))
            except Exception as e:
                logger.warning(f"Error in regex pattern {entity_type}: {e}")

        return entities

    def _detect_ner(self, text: str) -> List[PIIEntity]:
        """Detect PII using NER model (names, locations, orgs)"""
        if not self.ner_model:
            return []

        entities = []

        try:
            doc = self.ner_model(text)

            # Map spaCy entity labels to PII types
            label_mapping = {
                "PERSON": "PERSON",
                "GPE": "LOCATION",      # Geopolitical entity
                "LOC": "LOCATION",
                "ORG": "ORGANIZATION",
                "DATE": "DATE",
                "MONEY": "MONEY",
                "CARDINAL": "NUMBER",
            }

            for ent in doc.ents:
                if ent.label_ in label_mapping:
                    entities.append(PIIEntity(
                        entity_type=label_mapping[ent.label_],
                        text=ent.text,
                        start=ent.start_char,
                        end=ent.end_char,
                        confidence=0.85,  # NER confidence
                        detection_method="ner"
                    ))

        except Exception as e:
            logger.error(f"NER detection failed: {e}")

        return entities

    def _detect_custom(self, text: str) -> List[PIIEntity]:
        """
        Detect domain-specific PII patterns
        Override this method to add custom detection logic
        """
        # Example: Detect ages over 89 (HIPAA requirement)
        entities = []

        # Age pattern
        age_pattern = r'\b(?:age|aged)[\s:]*(\d{2,3})\b'
        for match in re.finditer(age_pattern, text, re.IGNORECASE):
            age = int(match.group(1))
            if age > 89:  # HIPAA considers >89 as PII
                entities.append(PIIEntity(
                    entity_type="AGE_OVER_89",
                    text=match.group(0),
                    start=match.start(),
                    end=match.end(),
                    confidence=0.9,
                    detection_method="custom"
                ))

        return entities

    def _load_patterns(self) -> Dict[str, str]:
        """Load regex patterns for PII detection"""
        from pii_guardian.patterns import get_all_patterns
        return get_all_patterns()

    def _load_ner_model(self):
        """Load NER model (spaCy)"""
        try:
            import spacy
            model_name = self.config.get("ner_model", "en_core_web_sm")
            return spacy.load(model_name)
        except ImportError:
            logger.warning("spaCy not installed. Install with: pip install spacy")
            return None
        except OSError:
            logger.warning(f"spaCy model not found. Install with: python -m spacy download en_core_web_sm")
            return None

    def _deduplicate_entities(self, entities: List[PIIEntity]) -> List[PIIEntity]:
        """
        Remove overlapping entities, keeping highest confidence

        Strategy:
        1. Sort by start position, then by confidence (descending)
        2. Keep non-overlapping entities with highest confidence
        """
        if not entities:
            return []

        # Sort by start position, then by confidence (descending)
        entities.sort(key=lambda e: (e.start, -e.confidence))

        deduplicated = []
        last_end = -1

        for entity in entities:
            # If this entity doesn't overlap with the last kept entity
            if entity.start >= last_end:
                deduplicated.append(entity)
                last_end = entity.end
            # If it overlaps but has higher confidence, replace
            elif deduplicated and entity.confidence > deduplicated[-1].confidence:
                deduplicated[-1] = entity
                last_end = entity.end

        return deduplicated


# Singleton instance (optional - for performance)
_detector_instance = None


def get_pii_detector(config: Optional[Dict[str, Any]] = None) -> PIIDetector:
    """Get or create PII detector singleton"""
    global _detector_instance
    if _detector_instance is None or config is not None:
        _detector_instance = PIIDetector(config)
    return _detector_instance
