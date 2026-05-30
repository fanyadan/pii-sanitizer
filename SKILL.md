---
name: pii-sanitizer
description: High-accuracy PII redaction using local LLM (gemma4:26b) with comprehensive global sector coverage.
version: 4.0.0
author: Hermes Agent
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [pii, privacy, redaction, llm, gemma, security, sanitization, global]
---

# PII Sanitizer Skill (Global v4.0)

This version features a significantly enhanced system prompt covering sensitive data across **all major global sectors** and regulatory frameworks.

## Key Improvements in v4.0

- Covers 10 major categories of sensitive data worldwide
- Explicit guidance on **re-identification risk**
- Supports GDPR, CCPA, PIPEDA, LGPD, PDPA, POPIA and other frameworks
- Conservative approach with clear decision rules
- Expanded placeholder types for better clarity

## Supported Sectors

- Healthcare & Medical
- Finance, Banking & Insurance
- Employment & HR
- Legal & Criminal Justice
- Education
- Government & Public Sector
- Technology & Digital Services
- Retail & E-commerce
- Real Estate
- Transportation & Logistics
- Telecommunications
- Energy & Utilities
- Media & Entertainment
- Non-profit & Charity

## Usage

```python
from pii_sanitizer import sanitize_text, sanitize_file

result = sanitize_text("Patient Elena Rodriguez, SSN 612-34-7890, Salary $125,000")
print(result["redacted_text"])
```

## Notes

- Uses local `gemma4:26b` model
- Supports multi-pass mode for higher accuracy
- **Always emit progress output** during LLM inference (user strongly dislikes silent execution on long-running tasks)
- Runs 100% locally with no data leaving your system
- Recommended for high-stakes or regulated environments