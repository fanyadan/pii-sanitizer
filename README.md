# pii-sanitizer

High-accuracy PII redaction powered by **local LLM (gemma4:26b)** with comprehensive coverage across all major global sectors and regulatory frameworks.

## Features

- **LLM-powered detection** — Uses contextual understanding instead of rigid rules
- **Global sector coverage** — Healthcare, Finance, Employment, Legal, Education, Government, Retail, Technology, and more
- **Re-identification risk awareness** — Redacts data that can identify individuals when combined
- **Progress output** — Shows status during each pass (no silent execution)
- **Retry logic** — Automatic retry on malformed output
- **Local execution** — Runs 100% locally via Ollama (no data leaves your machine)
- **Flexible output** — Returns structured JSON with redacted text and detected entities

## Version

**Current: v4.0** — Comprehensive global system prompt covering 10 major sensitive data categories and 14+ industry sectors.

## Install in Hermes Agent

### Via Hermes Command (Recommended)

```bash
hermes skills install https://raw.githubusercontent.com/fanyadan/pii-sanitizer/master/SKILL.md
```

This will download the skill into `~/.hermes/skills/pii-sanitizer/` and make it available automatically.

### Manual Installation

```bash
# Clone into Hermes skills directory
git clone <your-repo-url> ~/.hermes/skills/pii-sanitizer

# Or symlink from your workspace
ln -s ~/workspace/pii-sanitizer ~/.hermes/skills/pii-sanitizer
```

### Reload Skills

```bash
# In a Hermes session:
/reload-skills

# Or start fresh with the skill preloaded:
hermes -s pii-sanitizer
```

Once loaded, you can call `sanitize_text()` and `sanitize_file()` directly.

## Quick Start

```python
from pii_sanitizer import sanitize_text, sanitize_file

# Basic usage
result = sanitize_text("Patient Elena Rodriguez, SSN 612-34-7890, Policy #MED-2026-88421")
print(result["redacted_text"])
# => Patient [NAME], SSN [SSN], Policy [POLICY_NUMBER]

# High-accuracy mode (recommended)
result = sanitize_text(
    text,
    max_retries=3
)

# File processing
```

## Configuration

```python
from pii_sanitizer import PIISanitizer

sanitizer = PIISanitizer(
    model="gemma4:26b",      # Local Ollama model
    max_retries=3            # Retries on JSON parsing failure
)
```

## Output Structure

```json
{
  "original_length": 245,
  "redacted_length": 198,
  "entities_found": [
    {"type": "NAME", "original_value": "Elena Rodriguez"},
    {"type": "SSN", "original_value": "612-34-7890"},
    {"type": "POLICY_NUMBER", "original_value": "#MED-2026-88421"}
  ],
  "redacted_text": "Patient [NAME] (SSN: [SSN]) ...",
  "stats": {"total_entities": 3},
  "output_file": "/path/to/sanitized.txt"
}
```

## Requirements

- Python ≥ 3.10
- `ollama` Python package
- Local model `gemma4:26b` available via Ollama

```bash
pip install ollama
ollama pull gemma4:26b
```

## License

MIT