# PII Guardian

A reusable library for detecting and redacting Personally Identifiable Information (PII) from text.

## Features

- **Multi-layer Detection**: Regex patterns, NER models, and custom rules
- **Multiple Strategies**: Mask, remove, hash, or partial redaction
- **Selective Redaction**: Choose which entity types to redact
- **RAG Pipeline Ready**: Built-in support for document chunks
- **Flexible Configuration**: Constructor params, config objects, or environment variables
- **Type-Safe Results**: Structured `ProtectionResult` with metadata

## Quick Start

```python
from pii_guardian import PIIGuardian

# Simple usage
guardian = PIIGuardian()
result = guardian.protect("Contact: john@example.com, SSN: 123-45-6789")

print(result.text)        # Contact: [EMAIL], SSN: [SSN]
print(result.is_safe)     # False
print(result.pii_count)   # 2
```

## Installation

Add the `pii_guardian` directory to your Python path:

```python
import sys
sys.path.append('/path/to/project')

from pii_guardian import PIIGuardian
```

## Configuration

### Option 1: Constructor Parameters

```python
guardian = PIIGuardian(
    strategy="hash",
    confidence_threshold=0.9,
    enable_regex=True,
    enable_ner=False,
    redact_types=["EMAIL", "PHONE", "SSN"]
)
```

### Option 2: Config Object

```python
from pii_guardian import PIIConfig, PIIGuardian

config = PIIConfig(
    strategy="partial",
    confidence_threshold=0.8,
    redact_types=["EMAIL", "CREDIT_CARD"]
)

guardian = PIIGuardian(config=config)
```

### Option 3: Environment Variables

```bash
export PII_REDACTION_STRATEGY="mask"
export PII_CONFIDENCE_THRESHOLD="0.8"
export PII_ENABLE_REGEX="true"
export PII_ENABLE_NER="false"
export PII_REDACT_TYPES="EMAIL,PHONE,SSN"
```

```python
from pii_guardian import PIIConfig, PIIGuardian

config = PIIConfig.from_env()
guardian = PIIGuardian(config=config)
```

## Redaction Strategies

### Mask (default)
Replace PII with `[TYPE]` placeholder:
```python
guardian = PIIGuardian(strategy="mask")
result = guardian.protect("Email: john@test.com")
print(result.text)  # Email: [EMAIL]
```

### Remove
Complete removal with spacing:
```python
guardian = PIIGuardian(strategy="remove")
result = guardian.protect("Email: john@test.com")
print(result.text)  # Email:
```

### Hash
Replace with deterministic hash:
```python
guardian = PIIGuardian(strategy="hash")
result = guardian.protect("Email: john@test.com")
print(result.text)  # Email: [EMAIL-a1b2c3d4e5f6]
```

### Partial
Keep first and last characters:
```python
guardian = PIIGuardian(strategy="partial")
result = guardian.protect("Email: john@test.com")
print(result.text)  # Email: j***@***.com
```

## Use Cases

### 1. RAG Pipeline (Document Chunks)

```python
from pii_guardian import PIIGuardian

guardian = PIIGuardian()

chunks = [
    {"text": "SSN: 123-45-6789", "metadata": {"page": 1}},
    {"text": "Email: user@test.com", "metadata": {"page": 2}},
    {"text": "No PII here", "metadata": {"page": 3}}
]

# Redact PII in all chunks
redacted_chunks = guardian.protect_chunks(chunks)

# Check results
for chunk in redacted_chunks:
    print(f"Page {chunk['metadata']['page']}:")
    print(f"  Text: {chunk['text']}")
    print(f"  PII Found: {chunk['metadata'].get('pii_redacted', False)}")
    print(f"  PII Count: {chunk['metadata'].get('pii_count', 0)}")
```

### 2. Data Preprocessing

```python
from pii_guardian import PIIGuardian

guardian = PIIGuardian(strategy="hash")

# Clean sensitive data before storage
raw_data = [
    "User email: alice@example.com",
    "Customer phone: 555-123-4567",
    "Order total: $99.99"  # Not PII
]

clean_data = [guardian.protect(record).text for record in raw_data]
```

### 3. API Request/Response Filtering

```python
from pii_guardian import PIIGuardian

guardian = PIIGuardian(redact_types=["EMAIL", "PHONE"])

def sanitize_api_response(response_data: dict) -> dict:
    """Remove PII from API responses"""
    if "message" in response_data:
        result = guardian.protect(response_data["message"])
        response_data["message"] = result.text
    return response_data
```

### 4. Safe Logging

```python
import logging
from pii_guardian import PIIGuardian

guardian = PIIGuardian(strategy="mask")
logger = logging.getLogger(__name__)

def log_safely(message: str):
    """Log messages with PII redacted"""
    safe_message = guardian.protect(message).text
    logger.info(safe_message)

log_safely("User john@example.com logged in")
# Logs: "User [EMAIL] logged in"
```

### 5. Batch Processing

```python
from pii_guardian import PIIGuardian

guardian = PIIGuardian()

texts = [
    "Contact: john@test.com",
    "SSN: 123-45-6789",
    "No sensitive data"
]

results = guardian.protect_batch(texts)

for i, result in enumerate(results):
    print(f"Text {i+1}: {result.text}")
    print(f"  Has PII: {result.has_pii}")
    print(f"  PII Count: {result.pii_count}")
```

## API Reference

### PIIGuardian

Main facade class for PII protection.

#### Methods

- **`protect(text: str) -> ProtectionResult`**
  Detect and redact PII from text

- **`protect_batch(texts: List[str]) -> List[ProtectionResult]`**
  Protect multiple texts in batch

- **`protect_chunks(chunks: List[Dict], text_key="text") -> List[Dict]`**
  Protect PII in document chunks (RAG pipeline)

- **`is_safe(text: str, threshold: int = 0) -> bool`**
  Check if text contains PII

- **`detect_only(text: str) -> List[PIIEntity]`**
  Detect PII without redacting

### ProtectionResult

Result object with the following properties:

- **`text: str`** - Redacted text
- **`pii_count: int`** - Number of PII entities found
- **`entities: List[PIIEntity]`** - Detected PII entities
- **`redaction_map: Dict[str, str]`** - Original → redacted mapping
- **`audit_log: List[Dict]`** - Detailed audit entries
- **`is_safe: bool`** - True if no PII detected (property)
- **`has_pii: bool`** - True if PII detected (property)

### PIIEntity

Detected PII entity:

- **`entity_type: str`** - Type (e.g., "EMAIL", "SSN", "PHONE")
- **`text: str`** - The actual PII text
- **`start: int`** - Start position in text
- **`end: int`** - End position in text
- **`confidence: float`** - Detection confidence (0-1)
- **`detection_method: str`** - "regex", "ner", or "custom"

### PIIConfig

Configuration dataclass:

```python
@dataclass
class PIIConfig:
    strategy: str = "mask"
    confidence_threshold: float = 0.8
    enable_regex: bool = True
    enable_ner: bool = False
    ner_model: str = "en_core_web_sm"
    redact_types: List[str] = [...]  # See config.py for defaults
    audit_enabled: bool = True
    audit_log_path: str = "./logs/pii_audit.log"
```

## Supported PII Types

- **SSN**: Social Security Number
- **EMAIL**: Email addresses
- **PHONE**: Phone numbers
- **CREDIT_CARD**: Credit card numbers
- **ZIP_CODE**: US ZIP codes
- **IP_ADDRESS**: IPv4 addresses
- **URL**: Web URLs
- **STREET_ADDRESS**: Street addresses
- **DATE_OF_BIRTH**: Birth dates
- **BANK_ACCOUNT**: Bank account numbers
- **DRIVERS_LICENSE**: Driver's license numbers
- **PASSPORT**: Passport numbers
- **MEDICAL_RECORD**: Medical record numbers
- **PERSON**: Person names (requires NER)
- **LOCATION**: Geographic locations (requires NER)
- **ORGANIZATION**: Organization names (requires NER)

## Advanced Usage

### Custom Configuration

```python
from pii_guardian import PIIGuardian

# Only redact specific types
guardian = PIIGuardian(
    strategy="mask",
    redact_types=["SSN", "CREDIT_CARD", "PASSPORT"]
)

# Lower confidence threshold for more aggressive detection
guardian = PIIGuardian(
    confidence_threshold=0.7,
    enable_regex=True
)
```

### Enable NER (Named Entity Recognition)

Requires spaCy:

```bash
pip install spacy
python -m spacy download en_core_web_sm
```

```python
from pii_guardian import PIIGuardian

guardian = PIIGuardian(
    enable_ner=True,
    redact_types=["PERSON", "ORGANIZATION", "LOCATION"]
)

result = guardian.protect("John Smith works at Acme Corp in New York")
print(result.text)  # [PERSON] works at [ORGANIZATION] in [LOCATION]
```

### Access Low-Level Components

```python
from pii_guardian import PIIDetector, PIIRedactor

# Use detector and redactor separately
detector = PIIDetector({"enable_regex": True})
redactor = PIIRedactor(strategy="hash")

entities = detector.detect_all("Email: john@test.com")
result = redactor.redact("Email: john@test.com", entities)

print(result["redacted_text"])
```

## Error Handling

```python
from pii_guardian import PIIGuardian, PIIGuardianError, ConfigurationError

try:
    guardian = PIIGuardian(strategy="invalid")
except ConfigurationError as e:
    print(f"Configuration error: {e}")

try:
    result = guardian.protect("Some text")
except PIIGuardianError as e:
    print(f"Protection failed: {e}")
```

## License

Internal use only.
