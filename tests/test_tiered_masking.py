"""
Tests for tiered PII masking (compliance-aligned).

Tier 1 — direct identifiers (EMAIL, PHONE, SSN, ...): always masked.
Tier 2 — quasi-identifiers (PERSON, DATE_OF_BIRTH, ...): masked only when
         at least one Tier 1 entity is present in the same text.
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


def detector_with(always_mask, conditional_mask=None):
    """Build a PIIDetector with controlled tier config."""
    cfg = {
        "redact_types": always_mask,
        "enable_regex": True,
        "confidence_threshold": 0.0,
    }
    if conditional_mask is not None:
        cfg["conditional_mask_types"] = conditional_mask
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

    def test_to_dict_includes_conditional_mask_types(self):
        cfg = PIIConfig()
        d = cfg.to_dict()
        assert "conditional_mask_types" in d
        assert d["conditional_mask_types"] == cfg.conditional_mask_types

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
# Tier 2 Sensitive — detector unit tests
# ---------------------------------------------------------------------------

class TestDetectorTier2Sensitive:
    """
    Tier 2 sensitive entities (CREDIT_SCORE, CRIMINAL_HISTORY, EVICTION_HISTORY)
    are masked when Tier 1 is present OR when a PERSON entity is detected.
    """

    def _detector(self):
        return detector_with(
            always_mask=["EMAIL", "PHONE", "SSN"],
            conditional_mask=["PERSON", "DATE_OF_BIRTH"],
        )

    def _add_sensitive(self, d):
        d.config["sensitive_mask_types"] = [
            "CREDIT_SCORE", "CRIMINAL_HISTORY", "EVICTION_HISTORY"
        ]
        return d

    def test_sensitive_suppressed_with_no_context(self):
        """Sensitive attribute alone → not masked."""
        d = self._add_sensitive(self._detector())
        result = run_with_entities(d, [make_entity("CREDIT_SCORE", "credit score: 720")])
        assert result == []

    def test_sensitive_masked_when_tier1_present(self):
        """Sensitive attribute + Tier 1 → both masked."""
        d = self._add_sensitive(self._detector())
        result = run_with_entities(d, [
            make_entity("EMAIL", "a@b.com", start=0),
            make_entity("CRIMINAL_HISTORY", "prior felony conviction", start=20),
        ])
        types = {e.entity_type for e in result}
        assert "EMAIL" in types
        assert "CRIMINAL_HISTORY" in types

    def test_sensitive_masked_when_person_present(self):
        """Sensitive attribute + PERSON (no Tier 1) → both masked."""
        d = self._add_sensitive(self._detector())
        result = run_with_entities(d, [
            make_entity("PERSON", "John Smith", start=0),
            make_entity("EVICTION_HISTORY", "prior eviction", start=20),
        ])
        types = {e.entity_type for e in result}
        assert "EVICTION_HISTORY" in types

    def test_sensitive_not_masked_when_only_tier2_standard_present(self):
        """Sensitive attribute + DATE_OF_BIRTH (no Tier 1, no PERSON) → not masked."""
        d = self._add_sensitive(self._detector())
        result = run_with_entities(d, [
            make_entity("DATE_OF_BIRTH", "01/01/1980", start=0),
            make_entity("CREDIT_SCORE", "credit score: 580", start=20),
        ])
        # DATE_OF_BIRTH is Tier 2 standard (requires Tier 1) — also suppressed
        # CREDIT_SCORE is Tier 2 sensitive (requires Tier 1 or PERSON) — also suppressed
        assert result == []

    def test_all_three_sensitive_types_masked_with_person(self):
        """
        All three sensitive types unblocked by PERSON.
        Note: PERSON itself is Tier 2 standard and still requires Tier 1 to be
        masked — it acts only as a trigger here, not as a masked entity.
        """
        d = self._add_sensitive(self._detector())
        result = run_with_entities(d, [
            make_entity("PERSON", "Jane Doe", start=0),
            make_entity("CREDIT_SCORE", "credit score: 490", start=15),
            make_entity("CRIMINAL_HISTORY", "prior felony", start=40),
            make_entity("EVICTION_HISTORY", "prior eviction", start=60),
        ])
        types = {e.entity_type for e in result}
        assert types == {"CREDIT_SCORE", "CRIMINAL_HISTORY", "EVICTION_HISTORY"}
        assert "PERSON" not in types  # PERSON needs Tier 1 to be masked itself

    def test_tier2_standard_still_suppressed_when_only_person_triggers_sensitive(self):
        """
        PERSON triggers sensitive types but does NOT trigger Tier 2 standard
        (DATE_OF_BIRTH) — that still requires Tier 1.
        """
        d = self._add_sensitive(self._detector())
        result = run_with_entities(d, [
            make_entity("PERSON", "Jane Doe", start=0),
            make_entity("DATE_OF_BIRTH", "01/01/1980", start=15),
            make_entity("EVICTION_HISTORY", "prior eviction", start=40),
        ])
        types = {e.entity_type for e in result}
        # PERSON present: sensitive unblocked, but DATE_OF_BIRTH still needs Tier 1
        assert "EVICTION_HISTORY" in types
        assert "DATE_OF_BIRTH" not in types


# ---------------------------------------------------------------------------
# Tier 2 Sensitive — integration tests (regex-detectable)
# ---------------------------------------------------------------------------

class TestIntegrationTier2Sensitive:

    def setup_method(self):
        self.guardian = PIIGuardian(config=PIIConfig())

    def test_credit_score_suppressed_alone(self):
        result = self.guardian.protect("Applicant credit score: 620.")
        assert "[CREDIT_SCORE]" not in result.text
        assert result.is_safe

    def test_criminal_history_suppressed_alone(self):
        result = self.guardian.protect("Has a prior felony conviction.")
        assert "[CRIMINAL_HISTORY]" not in result.text
        assert result.is_safe

    def test_eviction_history_suppressed_alone(self):
        result = self.guardian.protect("Shows a prior eviction from 2019.")
        assert "[EVICTION_HISTORY]" not in result.text
        assert result.is_safe

    def test_credit_score_masked_when_email_present(self):
        result = self.guardian.protect("user@example.com, credit score: 580.")
        assert "[EMAIL]" in result.text
        assert "[CREDIT_SCORE]" in result.text

    def test_eviction_history_masked_when_ssn_present(self):
        result = self.guardian.protect("SSN: 123-45-6789, eviction record on file.")
        assert "[SSN]" in result.text
        assert "[EVICTION_HISTORY]" in result.text

    def test_criminal_history_masked_when_person_present(self):
        """
        PERSON triggers criminal history masking.
        PERSON itself is not masked (no Tier 1 present) — it only acts as a trigger.
        """
        guardian = PIIGuardian(config=PIIConfig())
        person_entity = make_entity("PERSON", "John Smith", start=0)
        guardian.detector.config["enable_ner"] = True
        guardian.detector.ner_model = object()
        with patch.object(guardian.detector, "_detect_ner", return_value=[person_entity]):
            result = guardian.protect("John Smith has a prior felony conviction.")
        assert "[CRIMINAL_HISTORY]" in result.text
        assert "John Smith" in result.text  # PERSON not masked without Tier 1

    def test_sensitive_not_masked_when_only_zip_present(self):
        """ZIP_CODE is Tier 2 standard — does not trigger sensitive masking."""
        result = self.guardian.protect("Zip 90210, credit score: 700.")
        assert "[CREDIT_SCORE]" not in result.text
