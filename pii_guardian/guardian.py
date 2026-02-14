"""
PII Guardian - Main Facade Class
Simple, unified API for PII detection and redaction using MASK strategy
"""
from typing import List, Dict, Any, Optional
import logging
from pii_guardian.detector import PIIDetector
from pii_guardian.redactor import PIIRedactor
from pii_guardian.config import PIIConfig
from pii_guardian.types import ProtectionResult, PIIEntity
from pii_guardian.exceptions import PIIGuardianError, ConfigurationError

logger = logging.getLogger(__name__)


class PIIGuardian:
    """
    Main facade for PII detection and redaction

    Uses MASK strategy: replaces PII with simple placeholders like [EMAIL], [PHONE], [SSN]

    Example:
        >>> guardian = PIIGuardian()
        >>> result = guardian.protect("Email: john@test.com")
        >>> print(result.text)
        Email: [EMAIL]
        >>> print(result.is_safe)
        False
    """

    def __init__(
        self,
        config: Optional[PIIConfig] = None,
        **kwargs
    ):
        """
        Initialize PII Guardian

        Args:
            config: PIIConfig instance (if provided, kwargs ignored)
            **kwargs: Configuration parameters:
                - confidence_threshold: float (default 0.8)
                - enable_regex: bool (default True)
                - enable_ner: bool (default False)
                - redact_types: List[str] (default: all sensitive types)

        Raises:
            ConfigurationError: If configuration is invalid

        Example:
            >>> guardian = PIIGuardian()
            >>> guardian = PIIGuardian(confidence_threshold=0.9)
            >>> guardian = PIIGuardian(config=PIIConfig.from_env())
        """
        try:
            # Build config
            if config is None:
                # Use kwargs or defaults
                config_dict = {
                    "confidence_threshold": kwargs.get("confidence_threshold", 0.8),
                    "enable_regex": kwargs.get("enable_regex", True),
                    "enable_ner": kwargs.get("enable_ner", False),
                    "ner_model": kwargs.get("ner_model", "en_core_web_sm"),
                    "redact_types": kwargs.get("redact_types", None),
                    "audit_enabled": kwargs.get("audit_enabled", True),
                    "audit_log_path": kwargs.get("audit_log_path", "./logs/pii_audit.log"),
                }
                # Remove None values
                config_dict = {k: v for k, v in config_dict.items() if v is not None}
                self.config = PIIConfig.from_dict(config_dict)
            else:
                self.config = config

            # Initialize detector and redactor (always uses MASK strategy)
            self.detector = PIIDetector(self.config.to_dict())
            self.redactor = PIIRedactor()

            logger.info(
                f"PIIGuardian initialized with MASK strategy, "
                f"confidence_threshold={self.config.confidence_threshold}"
            )

        except Exception as e:
            raise ConfigurationError(f"Failed to initialize PIIGuardian: {e}")

    def protect(self, text: str) -> ProtectionResult:
        """
        Detect and redact PII from text

        Args:
            text: Input text to protect

        Returns:
            ProtectionResult with redacted text and metadata

        Raises:
            PIIGuardianError: If protection fails

        Example:
            >>> guardian = PIIGuardian()
            >>> result = guardian.protect("SSN: 123-45-6789")
            >>> print(result.text)
            SSN: [SSN]
            >>> print(result.pii_count)
            1
        """
        try:
            # Detect PII
            entities = self.detector.detect_all(text)

            # Redact PII
            if entities:
                redaction_result = self.redactor.redact(text, entities)
                return ProtectionResult(
                    text=redaction_result["redacted_text"],
                    pii_count=redaction_result["pii_count"],
                    entities=entities,
                    redaction_map=redaction_result["redaction_map"],
                    audit_log=redaction_result["audit_log"],
                )
            else:
                # No PII found
                return ProtectionResult(
                    text=text,
                    pii_count=0,
                    entities=[],
                    redaction_map={},
                    audit_log=[],
                )

        except Exception as e:
            logger.error(f"Protection failed: {e}")
            raise PIIGuardianError(f"Failed to protect text: {e}")

    def protect_batch(self, texts: List[str]) -> List[ProtectionResult]:
        """
        Protect multiple texts in batch

        Args:
            texts: List of texts to protect

        Returns:
            List of ProtectionResult objects

        Example:
            >>> guardian = PIIGuardian()
            >>> results = guardian.protect_batch([
            ...     "Email: john@test.com",
            ...     "Phone: 555-1234"
            ... ])
            >>> print(results[0].has_pii)
            True
        """
        results = []
        for text in texts:
            try:
                results.append(self.protect(text))
            except Exception as e:
                logger.warning(f"Failed to protect text in batch: {e}")
                # Return original text with error indication
                results.append(ProtectionResult(
                    text=text,
                    pii_count=-1,  # Indicates error
                    entities=[],
                    redaction_map={},
                    audit_log=[{"error": str(e)}],
                ))
        return results

    def protect_chunks(
        self,
        chunks: List[Dict[str, Any]],
        text_key: str = "text"
    ) -> List[Dict[str, Any]]:
        """
        Protect PII in document chunks (RAG pipeline pattern)

        Args:
            chunks: List of chunk dicts with text and metadata
            text_key: Key containing the text to protect (default: "text")

        Returns:
            List of chunks with PII redacted and metadata updated

        Example:
            >>> guardian = PIIGuardian()
            >>> chunks = [
            ...     {"text": "SSN: 123-45-6789", "metadata": {"page": 1}},
            ...     {"text": "Email: user@test.com", "metadata": {"page": 2}}
            ... ]
            >>> redacted = guardian.protect_chunks(chunks)
            >>> print(redacted[0]["metadata"]["pii_redacted"])
            True
            >>> print(redacted[0]["text"])
            SSN: [SSN]
        """
        redacted_chunks = []

        for chunk in chunks:
            try:
                # Get text from chunk
                text = chunk.get(text_key, "")

                if not text:
                    redacted_chunks.append(chunk)
                    continue

                # Protect text
                result = self.protect(text)

                # Create new chunk with redacted text
                redacted_chunk = chunk.copy()
                redacted_chunk[text_key] = result.text

                # Update metadata
                if "metadata" not in redacted_chunk:
                    redacted_chunk["metadata"] = {}

                redacted_chunk["metadata"]["pii_redacted"] = result.has_pii
                redacted_chunk["metadata"]["pii_count"] = result.pii_count

                # Add entity types if PII found
                if result.has_pii:
                    entity_types = list(set(e.entity_type for e in result.entities))
                    redacted_chunk["metadata"]["pii_types"] = entity_types

                redacted_chunks.append(redacted_chunk)

            except Exception as e:
                logger.warning(f"Failed to protect chunk: {e}")
                redacted_chunks.append(chunk)

        logger.info(
            f"Protected {len(redacted_chunks)} chunks, "
            f"{sum(1 for c in redacted_chunks if c.get('metadata', {}).get('pii_redacted', False))} "
            f"contained PII"
        )

        return redacted_chunks

    def is_safe(self, text: str, threshold: int = 0) -> bool:
        """
        Check if text contains PII

        Args:
            text: Text to check
            threshold: Maximum allowed PII entities (default: 0)

        Returns:
            True if PII count <= threshold, False otherwise

        Example:
            >>> guardian = PIIGuardian()
            >>> guardian.is_safe("Hello world")
            True
            >>> guardian.is_safe("SSN: 123-45-6789")
            False
        """
        try:
            result = self.protect(text)
            return result.pii_count <= threshold
        except Exception as e:
            logger.error(f"Safety check failed: {e}")
            return False  # Fail-safe: assume unsafe if check fails

    def detect_only(self, text: str) -> List[PIIEntity]:
        """
        Detect PII without redacting (for analysis purposes)

        Args:
            text: Text to analyze

        Returns:
            List of detected PIIEntity objects

        Example:
            >>> guardian = PIIGuardian()
            >>> entities = guardian.detect_only("Email: john@test.com")
            >>> print(entities[0].entity_type)
            EMAIL
        """
        try:
            return self.detector.detect_all(text)
        except Exception as e:
            logger.error(f"Detection failed: {e}")
            raise PIIGuardianError(f"Failed to detect PII: {e}")
