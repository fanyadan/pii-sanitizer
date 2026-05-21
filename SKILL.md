---
name: pii-sanitizer
description: PII and sensitive data redaction using Microsoft Presidio. Supports text, code, logs, and multimodal inputs. Writes sanitized files and returns structured JSON results.
version: 0.1.0
author: Hermes Agent
tags: ["pii", "privacy", "redaction", "presidio", "security", "anonymization"]
---

# pii-sanitizer

Removes sensitive and private information (PII) from text, code, logs, and multimodal content using **Microsoft Presidio**.

## Project Structure

```
pii-sanitizer/
├── SKILL.md                  # This file (agent-facing skill definition)
├── README.md                 # Human-facing intro, install guide, API reference
├── pii_sanitizer.py          # Main module: PIISanitizer class + convenience functions
├── requirements.txt
├── examples/
│   └── sample_usage.py       # Minimal copy-paste usage examples
└── tests/
    ├── verify.py             # 6-test quick smoke test
    └── test_mixed_full.py    # 20-test full regression suite (text, image, mixed, edges)
```

## Features
- Text, code, logs, and image-based (OCR) input support
- Uses Presidio Analyzer + Anonymizer
- Returns structured JSON results + optionally writes sanitized file
- Configurable: allowlist, denylist, confidence threshold, hash mode
- CLI and Python API

## Custom Recognizers

All registered in `_add_chinese_recognizers()` on init. These extend Presidio's built-in recognizers:

| Recognizer | Entity Type | Pattern | Score | Context Keywords |
|------------|-------------|---------|-------|------------------|
| `chinese_phone` | `PHONE_NUMBER` | `1[3-9]\d{9}` | 0.85 | 手机, 电话, 联系方式 |
| `chinese_id` | `ID_CARD` | `\d{17}[\dXx]` | 0.90 | 身份证, 证件号 |
| `chinese_bank_card` | `CREDIT_CARD` | `\b62\d{14,17}\b` | 0.85 | 银行卡, 卡号, 储蓄卡, 信用卡, card |
| `aws_access_key` | `AWS_ACCESS_KEY` | `\bAKIA[A-Z0-9]{16}\b` | 0.95 | AWS, ACCESS_KEY, aws_access, secret |
| `api_secret_key` | `SECRET_KEY` | `\b[A-Za-z0-9+/=]{32,64}\b` | 0.75 | SECRET, secret, password, token, key, API |
| `credential_value` | `CREDENTIAL` | `["'][^\n"']{6,128}["']` | 0.80 | PASSWORD, SECRET, TOKEN, API_KEY, passwd, credential |

## Installation
```bash
pip install presidio-analyzer presidio-anonymizer spacy pytesseract pillow
python -m spacy download en_core_web_sm
# For Chinese: pip install spacy-pkuseg && python -m spacy download zh_core_web_sm
```

## Usage

### Python API
```python
from pii_sanitizer import sanitize_text, sanitize_file

result = sanitize_text("My email is test@example.com and phone is 13800138000")
print(result["redacted_text"])
print(result["entities_found"])

result = sanitize_file("input.log", output_path="sanitized.log")
```

### CLI
```bash
python -m pii_sanitizer --input data.txt --output sanitized.txt --json
```

### Multimodal (image)
```python
result = sanitize_text("Extract text from image and sanitize", image_path="screenshot.png")
```
**Design note:** When `image_path` is set, OCR-extracted text **replaces** the input text argument — they are not combined. The text argument is ignored in favor of the OCR result. This is by design — pass the image path alone and use the text argument as a description/comment.

### Hash-mode anonymization
```python
sanitizer = PIISanitizer(use_hash=True)
result = sanitizer.sanitize_text("Email: test@example.com")
# Entities are hashed with SHA256 instead of replaced with [REDACTED]
```
**Pitfall:** Presidio's `OperatorConfig` API requires `OperatorConfig("hash", {"hash_type": "sha256"})`, NOT a plain dict `{"type": "hash", ...}`. Using a dict raises `AttributeError: 'dict' object has no attribute 'operator_name'`.

### Verification
Two test suites available (run from skill root):

```bash
# Quick 6-test pass (text, code, logs, file I/O, OCR, schema)
python tests/verify.py

# Full 13-category regression suite (text, image, mixed, file I/O,
# allowlist/denylist, hash, code secrets, logs, edges, confidence, multi-OCR)
python tests/test_mixed_full.py
```

All tests are self-contained — the OCR tests dynamically generate PIL images with PII text, no external image files needed.

## Design Notes

- **OCR replaces text, not merges:** When `image_path` is set, OCR-extracted text replaces the input text argument. Pass the image path and use the text argument as a description/comment only.
- **`OperatorConfig` API:** Presidio's hash operator requires `OperatorConfig("hash", {"hash_type": "sha256"})`, not a plain dict. Using a dict raises `AttributeError: 'dict' object has no attribute 'operator_name'`.
- **Denylist is entity-aware:** Denylist filtering operates on entities *already detected by Presidio*, not on raw text. A denylist string that Presidio's built-in recognizers don't flag will never be redacted. For free-text matching, add a custom PatternRecognizer.

## Python Environment Pitfall

Presidio must be installed in the Python environment used to run the skill. If tests silently return 0 entities with `⚠️ FALLBACK MODE`, check `which python3` — the system Python (`/opt/homebrew/bin/python3` on macOS) likely lacks presidio. Use the conda/miniforge Python where presidio is installed:

```bash
/opt/homebrew/Caskroom/miniforge/base/bin/python3 tests/test_mixed_full.py
```

## Structured Output
Always returns:
```json
{
  "original_length": 123,
  "redacted_length": 98,
  "entities_found": [
    {"entity_type": "EMAIL_ADDRESS", "text": "test@example.com", "start": 12, "end": 28}
  ],
  "redacted_text": "My email is [REDACTED] ...",
  "output_file": "/path/to/sanitized/file",
  "stats": {"total_entities": 3, "by_type": {"EMAIL_ADDRESS": 1, "PHONE_NUMBER": 2}}
}
```

See `references/` for advanced configuration and Chinese entity recognizers.