"""
Tests for tiered PII masking (compliance-aligned).

Tier 1 — direct identifiers (EMAIL, PHONE, SSN, ...): always masked.
Tier 2 — quasi-identifiers (PERSON, DATE_OF_BIRTH, ...): masked when
         at least one Tier 1 entity is present OR a sensitive trigger type is present.
Sensitive trigger types (CREDIT_SCORE, CRIMINAL_HISTORY, EVICTION_HISTORY):
         their presence causes PERSON to be masked, but they are never masked themselves.
"""
import os
import pytest
from unittest.mock import patch

from pii_guardian.config import PIIConfig
from pii_guardian.detector import PIIDetector
from pii_guardian.guardian import PIIGuardian
from pii_guardian.types import PIIEntity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_entity(entity_type, text, start=0, confidence=0.95):
    return PIIEntity(
        entity_type=entity_type,
        text=text,
        start=start,
        end=start + len(text),
        confidence=confidence,
        detection_method="test",
    )


def detector_with(always_mask, conditional_mask=None, sensitive_triggers=None):
    """Build a PIIDetector with controlled tier config."""
    cfg = {
        "redact_types": always_mask,
        "enable_regex": True,
        "confidence_threshold": 0.0,
    }
    if conditional_mask is not None:
        cfg["conditional_mask_types"] = conditional_mask
    if sensitive_triggers is not None:
        cfg["sensitive_trigger_types"] = sensitive_triggers
    return PIIDetector(cfg)


def run_with_entities(detector, entities):
    """
    Call detect_all with fully mocked detection layers so that
    exactly `entities` flow through the tiered-filtering logic.
    """
    with patch.object(detector, "_detect_regex", return_value=entities), \
         patch.object(detector, "_detect_custom", return_value=[]):
        return detector.detect_all("dummy text")


# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------

class TestPIIConfig:
    def test_default_tier1_contains_direct_identifiers(self):
        cfg = PIIConfig()
        for t in ("EMAIL", "PHONE", "SSN", "CREDIT_CARD", "BANK_ACCOUNT",
                  "PASSPORT", "DRIVERS_LICENSE", "MEDICAL_RECORD", "IP_ADDRESS"):
            assert t in cfg.redact_types, f"{t} missing from Tier 1"

    def test_person_and_dob_moved_to_tier2(self):
        cfg = PIIConfig()
        assert "PERSON" not in cfg.redact_types
        assert "DATE_OF_BIRTH" not in cfg.redact_types

    def test_default_tier2_contains_quasi_identifiers(self):
        cfg = PIIConfig()
        for t in ("PERSON", "DATE_OF_BIRTH", "ZIP_CODE", "STREET_ADDRESS"):
            assert t in cfg.conditional_mask_types, f"{t} missing from Tier 2"

    def test_sensitive_types_not_in_redact_or_conditional(self):
        """Sensitive trigger types must not be in any masking list."""
        cfg = PIIConfig()
        for t in ("CREDIT_SCORE", "CRIMINAL_HISTORY", "EVICTION_HISTORY"):
            assert t not in cfg.redact_types
            assert t not in cfg.conditional_mask_types
            assert t in cfg.sensitive_trigger_types, f"{t} missing from sensitive_trigger_types"

    def test_to_dict_includes_conditional_mask_types(self):
        cfg = PIIConfig()
        d = cfg.to_dict()
        assert "conditional_mask_types" in d
        assert d["conditional_mask_types"] == cfg.conditional_mask_types

    def test_to_dict_includes_sensitive_trigger_types(self):
        cfg = PIIConfig()
        d = cfg.to_dict()
        assert "sensitive_trigger_types" in d
        assert d["sensitive_trigger_types"] == cfg.sensitive_trigger_types

    def test_from_env_reads_conditional_mask_types(self, monkeypatch):
        monkeypatch.setenv("PII_CONDITIONAL_MASK_TYPES", "PERSON,ZIP_CODE")
        cfg = PIIConfig.from_env()
        assert cfg.conditional_mask_types == ["PERSON", "ZIP_CODE"]

    def test_from_env_uses_default_when_env_absent(self, monkeypatch):
        monkeypatch.delenv("PII_CONDITIONAL_MASK_TYPES", raising=False)
        cfg = PIIConfig.from_env()
        assert "PERSON" in cfg.conditional_mask_types

    def test_from_env_whitespace_stripped(self, monkeypatch):
        monkeypatch.setenv("PII_CONDITIONAL_MASK_TYPES", " PERSON , DATE_OF_BIRTH ")
        cfg = PIIConfig.from_env()
        assert cfg.conditional_mask_types == ["PERSON", "DATE_OF_BIRTH"]

    def test_from_env_reads_sensitive_trigger_types(self, monkeypatch):
        monkeypatch.setenv("PII_SENSITIVE_TRIGGER_TYPES", "CRIMINAL_HISTORY,CREDIT_SCORE")
        cfg = PIIConfig.from_env()
        assert cfg.sensitive_trigger_types == ["CRIMINAL_HISTORY", "CREDIT_SCORE"]


# ---------------------------------------------------------------------------
# Detector — tiered filtering unit tests
# ---------------------------------------------------------------------------

class TestDetectorTieredFiltering:
    def test_tier1_entity_always_returned(self):
        d = detector_with(["EMAIL"], ["PERSON"])
        result = run_with_entities(d, [make_entity("EMAIL", "a@b.com")])
        assert len(result) == 1
        assert result[0].entity_type == "EMAIL"

    def test_tier2_entity_suppressed_without_tier1(self):
        """PERSON alone → detector returns nothing."""
        d = detector_with(["EMAIL"], ["PERSON"])
        result = run_with_entities(d, [make_entity("PERSON", "John Smith")])
        assert result == []

    def test_tier2_entity_included_when_tier1_present(self):
        d = detector_with(["EMAIL"], ["PERSON"])
        result = run_with_entities(d, [
            make_entity("EMAIL", "a@b.com", start=0),
            make_entity("PERSON", "John Smith", start=20),
        ])
        types = {e.entity_type for e in result}
        assert types == {"EMAIL", "PERSON"}

    def test_all_tier2_entities_included_when_any_tier1_present(self):
        """Every Tier 2 entity is unblocked by a single Tier 1 match."""
        d = detector_with(["SSN"], ["PERSON", "DATE_OF_BIRTH"])
        result = run_with_entities(d, [
            make_entity("SSN", "123-45-6789", start=0),
            make_entity("PERSON", "John Smith", start=20),
            make_entity("DATE_OF_BIRTH", "01/01/1980", start=40),
        ])
        types = {e.entity_type for e in result}
        assert types == {"SSN", "PERSON", "DATE_OF_BIRTH"}

    def test_all_tier2_suppressed_when_no_tier1(self):
        """Multiple Tier 2 entities with no Tier 1 → all suppressed."""
        d = detector_with(["SSN"], ["PERSON", "DATE_OF_BIRTH"])
        result = run_with_entities(d, [
            make_entity("PERSON", "John Smith", start=0),
            make_entity("DATE_OF_BIRTH", "01/01/1980", start=20),
        ])
        assert result == []

    def test_entity_not_in_either_tier_is_excluded(self):
        d = detector_with(["EMAIL"], ["PERSON"])
        result = run_with_entities(d, [make_entity("LOCATION", "New York")])
        assert result == []

    def test_multiple_tier1_entities_all_returned(self):
        d = detector_with(["EMAIL", "SSN"], ["PERSON"])
        result = run_with_entities(d, [
            make_entity("EMAIL", "a@b.com", start=0),
            make_entity("SSN", "123-45-6789", start=20),
        ])
        types = {e.entity_type for e in result}
        assert types == {"EMAIL", "SSN"}

    def test_empty_input_returns_empty(self):
        d = detector_with(["EMAIL"], ["PERSON"])
        result = run_with_entities(d, [])
        assert result == []


# ---------------------------------------------------------------------------
# Detector — backward-compatibility tests
# ---------------------------------------------------------------------------

class TestDetectorBackwardCompatibility:
    def test_no_conditional_mask_uses_flat_filter(self):
        """Code without conditional_mask_types falls through to the elif branch."""
        d = detector_with(["EMAIL"])  # no conditional_mask_types arg
        result = run_with_entities(d, [
            make_entity("EMAIL", "a@b.com", start=0),
            make_entity("PERSON", "John Smith", start=20),
        ])
        types = {e.entity_type for e in result}
        assert types == {"EMAIL"}
        assert "PERSON" not in types

    def test_flat_filter_excludes_non_listed_tier1(self):
        d = detector_with(["SSN"])
        result = run_with_entities(d, [make_entity("EMAIL", "a@b.com")])
        assert result == []

    def test_flat_filter_includes_listed_type(self):
        d = detector_with(["SSN", "EMAIL"])
        result = run_with_entities(d, [make_entity("SSN", "123-45-6789")])
        assert len(result) == 1
        assert result[0].entity_type == "SSN"


# ---------------------------------------------------------------------------
# Integration — regex-detectable types through PIIGuardian
# ---------------------------------------------------------------------------

class TestIntegrationRegexOnly:
    """
    End-to-end tests using PIIGuardian with the default tiered config.
    These cases rely only on regex (no NER / PERSON detection).
    """

    def setup_method(self):
        self.guardian = PIIGuardian(config=PIIConfig())

    # --- Tier 1 always masked ---

    def test_email_always_masked(self):
        result = self.guardian.protect("Email john@test.com please.")
        assert "[EMAIL]" in result.text
        assert result.has_pii

    def test_ssn_always_masked(self):
        result = self.guardian.protect("SSN: 123-45-6789")
        assert "[SSN]" in result.text

    def test_phone_always_masked(self):
        result = self.guardian.protect("Call me at 555-867-5309.")
        assert "[PHONE]" in result.text

    def test_no_pii_text_unchanged(self):
        text = "Hello, this is a clean sentence."
        result = self.guardian.protect(text)
        assert result.text == text
        assert result.is_safe

    # --- Tier 2 (ZIP_CODE) ---

    def test_zip_suppressed_without_tier1(self):
        """ZIP_CODE is Tier 2; no direct identifier → not masked."""
        result = self.guardian.protect("I live in 90210.")
        assert "[ZIP_CODE]" not in result.text
        assert result.is_safe

    def test_zip_masked_when_email_present(self):
        """ZIP_CODE is Tier 2; EMAIL present → both masked."""
        result = self.guardian.protect("Email me at user@example.com, zip 90210.")
        assert "[EMAIL]" in result.text
        assert "[ZIP_CODE]" in result.text

    def test_zip_masked_when_ssn_present(self):
        result = self.guardian.protect("SSN: 123-45-6789, zip 10001.")
        assert "[SSN]" in result.text
        assert "[ZIP_CODE]" in result.text

    # --- Tier 2 (STREET_ADDRESS) ---

    def test_street_address_suppressed_without_tier1(self):
        """STREET_ADDRESS is Tier 2; no direct identifier → not masked."""
        result = self.guardian.protect("Meet me at 123 Main Street.")
        assert "[STREET_ADDRESS]" not in result.text
        assert result.is_safe

    def test_street_address_masked_when_ssn_present(self):
        """STREET_ADDRESS is Tier 2; SSN present → both masked."""
        result = self.guardian.protect("SSN: 123-45-6789, live at 456 Oak Avenue.")
        assert "[SSN]" in result.text
        assert "[STREET_ADDRESS]" in result.text

    def test_street_address_masked_when_email_present(self):
        result = self.guardian.protect("Contact user@test.com at 789 Elm Drive.")
        assert "[EMAIL]" in result.text
        assert "[STREET_ADDRESS]" in result.text

    # --- Multiple Tier 1 types ---

    def test_multiple_tier1_types_all_masked(self):
        result = self.guardian.protect("Email: a@b.com, SSN: 123-45-6789")
        assert "[EMAIL]" in result.text
        assert "[SSN]" in result.text


# ---------------------------------------------------------------------------
# Integration — plan verification cases (PERSON via mocked NER)
# ---------------------------------------------------------------------------

class TestIntegrationPlanVerificationCases:
    """
    Reproduces the six verification cases from the plan.
    PERSON is not regex-detectable so NER is mocked via patch.object.
    """

    def _guardian_with_person(self, person_text, start=0):
        """Return a PIIGuardian whose NER layer injects one PERSON entity."""
        cfg = PIIConfig()
        guardian = PIIGuardian(config=cfg)
        person_entity = make_entity("PERSON", person_text, start=start)
        guardian.detector.config["enable_ner"] = True
        guardian.detector.ner_model = object()  # truthy sentinel
        self._ner_patch = patch.object(
            guardian.detector, "_detect_ner", return_value=[person_entity]
        )
        self._ner_patch.start()
        return guardian

    def teardown_method(self):
        patch.stopall()

    def test_person_alone_not_masked(self):
        """'Call John Smith.' → no masking (PERSON alone, no Tier 1)."""
        guardian = self._guardian_with_person("John Smith", start=5)
        result = guardian.protect("Call John Smith.")
        assert "[PERSON]" not in result.text
        assert result.is_safe

    def test_email_tier1_always_masked(self):
        """'Email john@test.com.' → [EMAIL] (Tier 1 always masked)."""
        cfg = PIIConfig()
        guardian = PIIGuardian(config=cfg)
        result = guardian.protect("Email john@test.com.")
        assert "[EMAIL]" in result.text

    def test_email_triggers_person_masking(self):
        """'John Smith, john@test.com' → both [PERSON] and [EMAIL] masked."""
        guardian = self._guardian_with_person("John Smith", start=0)
        result = guardian.protect("John Smith, john@test.com")
        assert "[EMAIL]" in result.text
        assert "[PERSON]" in result.text

    def test_ssn_triggers_person_masking(self):
        """'SSN: 123-45-6789, John Smith' → both masked."""
        guardian = self._guardian_with_person("John Smith", start=19)
        result = guardian.protect("SSN: 123-45-6789, John Smith")
        assert "[SSN]" in result.text
        assert "[PERSON]" in result.text

    def test_person_with_age_and_city_not_masked(self):
        """'John Smith, age 35, NYC' → no masking (only quasi-identifiers)."""
        guardian = self._guardian_with_person("John Smith", start=0)
        result = guardian.protect("John Smith, age 35, NYC")
        assert "[PERSON]" not in result.text
        assert result.is_safe

    def test_phone_triggers_person_masking(self):
        """'John Smith, 555-867-5309' → both [PERSON] and [PHONE] masked."""
        guardian = self._guardian_with_person("John Smith", start=0)
        result = guardian.protect("John Smith, 555-867-5309")
        assert "[PERSON]" in result.text
        assert "[PHONE]" in result.text


# ---------------------------------------------------------------------------
# Sensitive trigger types — detector unit tests
# ---------------------------------------------------------------------------

class TestDetectorSensitiveTriggers:
    """
    Sensitive trigger types (CREDIT_SCORE, CRIMINAL_HISTORY, EVICTION_HISTORY)
    cause PERSON to be masked but are never masked themselves.
    """

    def _detector(self):
        return detector_with(
            always_mask=["EMAIL", "PHONE", "SSN"],
            conditional_mask=["PERSON", "DATE_OF_BIRTH"],
            sensitive_triggers=["CREDIT_SCORE", "CRIMINAL_HISTORY", "EVICTION_HISTORY"],
        )

    def test_sensitive_type_alone_never_in_output(self):
        """Sensitive trigger alone → nothing in output (not masked)."""
        d = self._detector()
        result = run_with_entities(d, [make_entity("CREDIT_SCORE", "credit score: 720")])
        assert result == []

    def test_sensitive_trigger_causes_person_to_be_masked(self):
        """PERSON + sensitive trigger (no Tier 1) → PERSON masked, sensitive NOT in output."""
        d = self._detector()
        result = run_with_entities(d, [
            make_entity("PERSON", "John Smith", start=0),
            make_entity("CRIMINAL_HISTORY", "prior felony conviction", start=20),
        ])
        types = {e.entity_type for e in result}
        assert "PERSON" in types
        assert "CRIMINAL_HISTORY" not in types  # never masked, stays as plain text

    def test_sensitive_trigger_also_causes_dob_to_be_masked(self):
        """PERSON + DOB + sensitive trigger → PERSON and DOB both masked, sensitive NOT in output."""
        d = self._detector()
        result = run_with_entities(d, [
            make_entity("PERSON", "Jane Doe", start=0),
            make_entity("DATE_OF_BIRTH", "01/01/1980", start=15),
            make_entity("EVICTION_HISTORY", "prior eviction", start=40),
        ])
        types = {e.entity_type for e in result}
        assert "PERSON" in types
        assert "DATE_OF_BIRTH" in types
        assert "EVICTION_HISTORY" not in types

    def test_sensitive_trigger_alone_no_person_nothing_masked(self):
        """Sensitive trigger with no PERSON and no Tier 1 → nothing masked."""
        d = self._detector()
        result = run_with_entities(d, [make_entity("EVICTION_HISTORY", "prior eviction")])
        assert result == []

    def test_tier1_still_masks_person(self):
        """Tier 1 + PERSON (no sensitive trigger) → both masked (existing behavior preserved)."""
        d = self._detector()
        result = run_with_entities(d, [
            make_entity("EMAIL", "a@b.com", start=0),
            make_entity("PERSON", "John Smith", start=20),
        ])
        types = {e.entity_type for e in result}
        assert "EMAIL" in types
        assert "PERSON" in types

    def test_tier1_present_sensitive_still_not_in_output(self):
        """Tier 1 + sensitive trigger → Tier 1 masked, sensitive NOT in output."""
        d = self._detector()
        result = run_with_entities(d, [
            make_entity("EMAIL", "a@b.com", start=0),
            make_entity("CRIMINAL_HISTORY", "prior felony", start=20),
        ])
        types = {e.entity_type for e in result}
        assert "EMAIL" in types
        assert "CRIMINAL_HISTORY" not in types

    def test_all_three_sensitive_types_never_in_output(self):
        """All three sensitive triggers with PERSON → PERSON masked, none of the sensitive types."""
        d = self._detector()
        result = run_with_entities(d, [
            make_entity("PERSON", "Jane Doe", start=0),
            make_entity("CREDIT_SCORE", "credit score: 490", start=15),
            make_entity("CRIMINAL_HISTORY", "prior felony", start=40),
            make_entity("EVICTION_HISTORY", "prior eviction", start=60),
        ])
        types = {e.entity_type for e in result}
        assert types == {"PERSON"}  # only PERSON masked, sensitive types stay as plain text


# ---------------------------------------------------------------------------
# Sensitive trigger types — integration tests (regex-detectable)
# ---------------------------------------------------------------------------

class TestIntegrationSensitiveTriggers:

    def setup_method(self):
        self.guardian = PIIGuardian(config=PIIConfig())

    def test_credit_score_never_masked(self):
        result = self.guardian.protect("Applicant credit score: 620.")
        assert "[CREDIT_SCORE]" not in result.text
        assert result.is_safe

    def test_criminal_history_never_masked(self):
        result = self.guardian.protect("Has a prior felony conviction.")
        assert "[CRIMINAL_HISTORY]" not in result.text
        assert result.is_safe

    def test_eviction_history_never_masked(self):
        result = self.guardian.protect("Shows a prior eviction from 2019.")
        assert "[EVICTION_HISTORY]" not in result.text
        assert result.is_safe

    def test_criminal_history_triggers_person_masking(self):
        """
        PERSON + criminal history → PERSON masked, criminal history stays visible.
        "John Smith has a prior felony conviction." → "[PERSON] has a prior felony conviction."
        """
        guardian = PIIGuardian(config=PIIConfig())
        person_entity = make_entity("PERSON", "John Smith", start=0)
        guardian.detector.config["enable_ner"] = True
        guardian.detector.ner_model = object()
        with patch.object(guardian.detector, "_detect_ner", return_value=[person_entity]):
            result = guardian.protect("John Smith has a prior felony conviction.")
        assert "[PERSON]" in result.text
        assert "[CRIMINAL_HISTORY]" not in result.text
        assert "prior felony conviction" in result.text

    def test_credit_score_triggers_person_masking(self):
        """PERSON + credit score → PERSON masked, credit score stays visible."""
        guardian = PIIGuardian(config=PIIConfig())
        person_entity = make_entity("PERSON", "Jane Doe", start=0)
        guardian.detector.config["enable_ner"] = True
        guardian.detector.ner_model = object()
        with patch.object(guardian.detector, "_detect_ner", return_value=[person_entity]):
            result = guardian.protect("Jane Doe, credit score: 580.")
        assert "[PERSON]" in result.text
        assert "[CREDIT_SCORE]" not in result.text
        assert "credit score" in result.text

    def test_eviction_history_triggers_person_masking(self):
        """PERSON + eviction history → PERSON masked, eviction history stays visible."""
        guardian = PIIGuardian(config=PIIConfig())
        person_entity = make_entity("PERSON", "John Smith", start=0)
        guardian.detector.config["enable_ner"] = True
        guardian.detector.ner_model = object()
        with patch.object(guardian.detector, "_detect_ner", return_value=[person_entity]):
            result = guardian.protect("John Smith has a prior eviction record.")
        assert "[PERSON]" in result.text
        assert "[EVICTION_HISTORY]" not in result.text
        assert "prior eviction record" in result.text

    def test_email_present_sensitive_type_stays_visible(self):
        """Tier 1 (EMAIL) present + credit score → EMAIL masked, credit score stays as-is."""
        result = self.guardian.protect("user@example.com, credit score: 580.")
        assert "[EMAIL]" in result.text
        assert "[CREDIT_SCORE]" not in result.text
        assert "credit score" in result.text
