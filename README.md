# PII Guardian

A reusable Python library for detecting and redacting Personally Identifiable Information (PII) from text using simple placeholders.

## Features

- 🔒 Multi-layer PII detection (Regex + NER + Custom Rules)
- 🎯 MASK strategy: Simple placeholders like [EMAIL], [PHONE], [SSN]
- 🎨 Selective redaction by entity type
- ⚡ Simple one-line API
- 📦 Zero required dependencies (NER is optional)
- 🔧 Flexible configuration
- 📊 Type-safe with full type hints

## Installation

### From Source (Development)

```bash
# Clone or download the repository
cd pii-guardian

# Install in development mode
pip install -e .

# Or install with NER support
pip install -e ".[ner]"
```

### Using pip (Local)

```bash
pip install .
```

## Quick Start

```python
from pii_guardian import PIIGuardian

# Create guardian
guardian = PIIGuardian()

# Protect text - PII becomes [EMAIL], [PHONE], [SSN], etc.
result = guardian.protect("Email: john@example.com, SSN: 123-45-6789")

print(result.text)        # Email: [EMAIL], SSN: [SSN]
print(result.pii_count)   # 2
print(result.is_safe)     # False
```

## How It Works

PII Guardian uses the **MASK strategy**: it replaces detected PII with simple, clear placeholders.

### Examples

| Original | Protected |
|----------|-----------|
| john@example.com | `[EMAIL]` |
| 555-123-4567 | `[PHONE]` |
| 123-45-6789 | `[SSN]` |
| John Smith | `[PERSON]` (with NER) |
| San Francisco | `[LOCATION]` (with NER) |

## Usage Examples

### RAG Pipeline (Document Chunks)

```python
from pii_guardian import PIIGuardian

guardian = PIIGuardian()

chunks = [
    {"text": "SSN: 123-45-6789", "metadata": {"page": 1}},
    {"text": "Email: user@test.com", "metadata": {"page": 2}}
]

# Protect all chunks
protected = guardian.protect_chunks(chunks)

# Chunks now have PII redacted + metadata updated
for chunk in protected:
    print(chunk["text"])
    print(chunk["metadata"]["pii_redacted"])  # True/False
    print(chunk["metadata"]["pii_count"])      # Number of PII entities
```

### Batch Processing

```python
from pii_guardian import PIIGuardian

guardian = PIIGuardian()

texts = [
    "Email: alice@example.com",
    "Phone: 555-1234",
    "No PII here"
]

results = guardian.protect_batch(texts)

for result in results:
    print(f"Protected: {result.text}, PII: {result.pii_count}")
```

### Configuration

```python
from pii_guardian import PIIGuardian, PIIConfig

# Using constructor parameters
guardian = PIIGuardian(
    confidence_threshold=0.9,
    redact_types=["EMAIL", "PHONE", "SSN"]
)

# Using config object
config = PIIConfig(
    enable_regex=True,
    redact_types=["SSN", "CREDIT_CARD"]
)
guardian = PIIGuardian(config=config)

# From environment variables
config = PIIConfig.from_env()
guardian = PIIGuardian(config=config)
```

## Supported PII Types

- **SSN** - Social Security Number
- **EMAIL** - Email addresses
- **PHONE** - Phone numbers
- **CREDIT_CARD** - Credit card numbers
- **IP_ADDRESS** - IP addresses
- **URL** - Web URLs
- **STREET_ADDRESS** - Street addresses
- **DATE_OF_BIRTH** - Birth dates
- **BANK_ACCOUNT** - Bank account numbers
- **DRIVERS_LICENSE** - Driver's licenses
- **PASSPORT** - Passport numbers
- **MEDICAL_RECORD** - Medical records
- **PERSON** - Names (requires NER)
- **LOCATION** - Locations (requires NER)
- **ORGANIZATION** - Organizations (requires NER)

## API Reference

### PIIGuardian

Main class for PII protection.

**Methods:**
- `protect(text: str) -> ProtectionResult`: Detect and redact PII from text
- `protect_batch(texts: List[str]) -> List[ProtectionResult]`: Protect multiple texts
- `protect_chunks(chunks: List[Dict]) -> List[Dict]`: Protect document chunks (RAG pipeline)
- `is_safe(text: str, threshold: int = 0) -> bool`: Check if text contains PII
- `detect_only(text: str) -> List[PIIEntity]`: Detect PII without redacting

### ProtectionResult

Result object with PII protection details.

**Properties:**
- `text: str` - Redacted text (with [TYPE] placeholders)
- `pii_count: int` - Number of PII entities found
- `entities: List[PIIEntity]` - Detected PII entities
- `redaction_map: Dict[str, str]` - Original → [TYPE] mapping
- `audit_log: List[Dict]` - Detailed audit entries
- `is_safe: bool` - True if no PII detected
- `has_pii: bool` - True if PII detected

## Documentation

For complete documentation, see [pii_guardian/README.md](pii_guardian/README.md)

## License

MIT License - see LICENSE file for details

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

For issues and questions, please open an issue on GitHub.
