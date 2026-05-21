# pii-sanitizer

Privacy-preserving data redaction powered by **Microsoft Presidio**. Detects and removes personally identifiable information (PII) from text, code, system logs, and images (via OCR) — with first-class support for Chinese entities.

## Features

- **Text, code, and log sanitization** — emails, phone numbers, IPs, IDs, dates
- **Image OCR** — extract text from screenshots and redact PII in one pass
- **Chinese-first** — 手机号, 身份证, 银行卡号, 姓名 built in
- **Security-oriented** — AWS access keys, API secrets, JWT tokens, credential assignments
- **Flexible output** — replace with `<ENTITY_TYPE>` markers, SHA256 hashes, or write sanitized files
- **Configurable** — allowlist/denylist, confidence threshold, entity filtering
- **Graceful fallback** — runs without Presidio installed (pass-through mode with clear warning)

## Install in Hermes Agent

This skill lives at **[github.com/fanyadan/pii-sanitizer](https://github.com/fanyadan/pii-sanitizer)**.

### From GitHub (hub install)

```bash
hermes skills install https://raw.githubusercontent.com/fanyadan/pii-sanitizer/master/SKILL.md
```

This downloads the skill into `~/.hermes/skills/pii-sanitizer/` and Hermes picks it up automatically.

### Manual (clone yourself)

```bash
git clone git@github.com:fanyadan/pii-sanitizer.git ~/.hermes/skills/pii-sanitizer

# or symlink:
git clone git@github.com:fanyadan/pii-sanitizer.git ~/workspace/pii-sanitizer
ln -s ~/workspace/pii-sanitizer ~/.hermes/skills/pii-sanitizer
```

Then reload:

```bash
# In a Hermes session:
/reload-skills

# Or start fresh with the skill preloaded:
hermes -s pii-sanitizer
```

Once loaded, Hermes will call `sanitize_text` / `sanitize_file` whenever you ask it to redact PII.

## PyPI / pip Installation

```bash
# Core (required)
pip install presidio-analyzer presidio-anonymizer

# OCR support (optional — for image redaction)
pip install pytesseract pillow
brew install tesseract tesseract-lang   # macOS
# or: apt install tesseract-ocr tesseract-ocr-chi-sim  # Linux

# spaCy language models (recommended for NER)
python -m spacy download en_core_web_sm

# Or use the bundled requirements file:
pip install -r requirements.txt
```

## Quick Start

```python
from pii_sanitizer import sanitize_text, sanitize_file

# Text
result = sanitize_text("联系我：13800138000，邮箱 test@company.com，身份证 110101199001011234")
print(result["redacted_text"])
# => 联系我：<PHONE_NUMBER>，邮箱 <EMAIL_ADDRESS>，身份证 <ID_CARD>

print(result["stats"])
# => {'total_entities': 3, 'by_type': {'PHONE_NUMBER': 2, 'EMAIL_ADDRESS': 1, ...}}

# Image OCR
result = sanitize_text("Extract and sanitize", image_path="screenshot.png")

# File I/O
result = sanitize_file("server.log", output_path="server.clean.log")
```

## CLI

```bash
python -m pii_sanitizer --input data.txt --output sanitized.txt --json
python -m pii_sanitizer --input "Phone: 13800138000" --json --hash
```

## Configuration

```python
from pii_sanitizer import PIISanitizer

sanitizer = PIISanitizer(
    language="en",              # spaCy language model
    confidence_threshold=0.6,   # min score to redact (0.0–1.0)
    use_hash=True,              # SHA256 instead of <ENTITY_TYPE> markers
    allowlist=["safe@keep.com"], # never redact these
    denylist=["force-hide-me"],  # always redact these if detected
)
```

## Detected Entity Types

| Category | Entity Types |
|----------|-------------|
| Standard | `EMAIL_ADDRESS`, `PHONE_NUMBER`, `IP_ADDRESS`, `DATE_TIME`, `PERSON`, `URL`, `NRP` |
| Chinese | `ID_CARD` (身份证), `CREDIT_CARD` (银行卡), Chinese `PHONE_NUMBER` (手机号) |
| Security | `AWS_ACCESS_KEY`, `SECRET_KEY`, `CREDENTIAL` |

## Output Schema

Every call returns:

```json
{
  "original_length": 123,
  "redacted_length": 98,
  "entities_found": [
    {"entity_type": "EMAIL_ADDRESS", "text": "test@example.com", "start": 12, "end": 28, "score": 1.0}
  ],
  "redacted_text": "Email: <EMAIL_ADDRESS> ...",
  "stats": {"total_entities": 3, "by_type": {"EMAIL_ADDRESS": 1, "PHONE_NUMBER": 2}},
  "output_file": null
}
```

## Verification

Two test suites included — all self-contained, no external files needed:

```bash
# Quick smoke test (6 tests)
python tests/verify.py

# Full mixed-mode test (20 tests: text, image, file I/O, edge cases)
python tests/test_mixed_full.py
```

Expected output: `✅ ALL CHECKS PASSED — skill works 100% as expected`

## How It Works

```
Input (text / image) → Presidio Analyzer → Entity detection
                                        → Custom recognizers (Chinese, AWS, secrets)
                                        → Allowlist/denylist filtering
                                        → Confidence threshold
                     → Presidio Anonymizer → Replace / hash
                     → Structured JSON output
```

When `image_path` is provided, the image is OCR'd with Tesseract and the extracted text replaces the input text before Presidio processing.

## Requirements

- Python ≥ 3.10
- **Presidio** ≥ 2.2 (analyzer + anonymizer)
- **spaCy** ≥ 3.7 (NER)
- **Tesseract** + **pytesseract** (image OCR, optional)
- **Pillow** ≥ 10.0 (image generation for tests, optional)

## License

MIT
