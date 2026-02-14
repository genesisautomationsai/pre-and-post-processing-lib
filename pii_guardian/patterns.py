"""
Regex patterns for PII detection
Comprehensive patterns for various PII types
"""

# Core PII patterns
PII_PATTERNS = {
    # Social Security Number (US)
    "SSN": r'\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b',

    # Phone Numbers (various formats)
    "PHONE": r'\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b',

    # Email Addresses
    "EMAIL": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',

    # Credit Card Numbers
    "CREDIT_CARD": r'\b(?:\d{4}[-\s]?){3}\d{4}\b',

    # US ZIP Codes
    "ZIP_CODE": r'\b\d{5}(?:-\d{4})?\b',

    # IP Addresses (IPv4)
    "IP_ADDRESS": r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',

    # URLs
    "URL": r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&/=]*)',

    # US Street Addresses (basic pattern)
    "STREET_ADDRESS": r'\b\d{1,5}\s+[\w\s]{1,50}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\.?\b',

    # Date of Birth patterns
    "DATE_OF_BIRTH": r'\b(?:0?[1-9]|1[0-2])[/-](?:0?[1-9]|[12]\d|3[01])[/-](?:19|20)\d{2}\b',

    # Bank Account Numbers (8-17 digits)
    "BANK_ACCOUNT": r'\b\d{8,17}\b',

    # Driver's License (varies by state, general pattern)
    "DRIVERS_LICENSE": r'\b[A-Z]{1,2}\d{5,8}\b',

    # Passport Number (US format)
    "PASSPORT": r'\b[A-Z]\d{8}\b',

    # Medical Record Number
    "MEDICAL_RECORD": r'\b(?:MRN|Medical\s+Record)[:\s#]*([A-Z0-9]{6,12})\b',
}

# Domain-specific patterns
DOMAIN_SPECIFIC_PATTERNS = {
    "EMPLOYEE_ID": r'\b(?:EMP|EMPLOYEE)[:\s#-]*([A-Z0-9]{4,10})\b',
    "POLICY_NUMBER": r'\b(?:POL|Policy)[:\s#-]*([A-Z0-9]{6,15})\b',
    "ACCOUNT_NUMBER": r'\b(?:ACCT|Account)[:\s#-]*(\d{6,15})\b',
}


def get_all_patterns():
    """Get all PII patterns combined"""
    return {**PII_PATTERNS, **DOMAIN_SPECIFIC_PATTERNS}


# Context-based patterns (require surrounding text analysis)
CONTEXTUAL_PATTERNS = {
    "SALARY": r'\$\s*\d{2,3},?\d{3}(?:\.\d{2})?\s*(?:per|/)\s*(?:year|annum|yr)',
    "AGE_OVER_89": r'\b(?:age|aged)[\s:]*(?:9[0-9]|1[0-9]{2})\b',  # HIPAA requirement
}


def get_sensitive_patterns():
    """Get patterns for highly sensitive data only"""
    return {
        "SSN": PII_PATTERNS["SSN"],
        "CREDIT_CARD": PII_PATTERNS["CREDIT_CARD"],
        "BANK_ACCOUNT": PII_PATTERNS["BANK_ACCOUNT"],
        "MEDICAL_RECORD": PII_PATTERNS["MEDICAL_RECORD"],
        "PASSPORT": PII_PATTERNS["PASSPORT"],
    }
