"""
Setup configuration for PII Guardian library
"""
from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
this_directory = Path(__file__).parent
long_description = (this_directory / "pii_guardian" / "README.md").read_text()

setup(
    name="pii-guardian",
    version="1.0.0",
    author="PII Guardian Team",
    author_email="your-email@example.com",
    description="A reusable library for detecting and redacting Personally Identifiable Information (PII) from text",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/pii-guardian",
    packages=find_packages(exclude=["tests", "tests.*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Text Processing",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
    install_requires=[
        # Core dependencies (none required - all optional)
    ],
    extras_require={
        "ner": [
            "spacy>=3.0.0",
        ],
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "mypy>=0.990",
        ],
    },
    entry_points={
        "console_scripts": [
            "pii-guardian=pii_guardian.cli:main",
        ],
    },
    keywords="pii security redaction privacy gdpr hipaa data-protection",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/pii-guardian/issues",
        "Source": "https://github.com/yourusername/pii-guardian",
        "Documentation": "https://github.com/yourusername/pii-guardian/blob/main/pii_guardian/README.md",
    },
    include_package_data=True,
    zip_safe=False,
)
