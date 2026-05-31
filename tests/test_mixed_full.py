#!/usr/bin/env python3
"""
Tests for the pii-sanitizer skill.
Includes both prompt contract checks and real functional verification
using the live local LLM (gemma4:26b) with multi-pass strategy.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
import pii_sanitizer


def _balanced_json_after(label, text):
    label_pos = text.index(label)
    start = text.index("{", label_pos)
    depth = 0
    in_string = False
    escaped = False

    for index in range(start, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]

    raise ValueError(f"No balanced JSON object found after {label!r}")


def _example_input():
    marker = 'Input: "'
    start = pii_sanitizer.FEW_SHOT_EXAMPLES.index(marker) + len(marker)
    end = pii_sanitizer.FEW_SHOT_EXAMPLES.index('"', start)
    return pii_sanitizer.FEW_SHOT_EXAMPLES[start:end]


def _example_output():
    raw_json = _balanced_json_after("Output:", pii_sanitizer.FEW_SHOT_EXAMPLES)
    return json.loads(raw_json)


def test_exports_few_shot_examples():
    assert isinstance(pii_sanitizer.FEW_SHOT_EXAMPLES, str)
    assert "Example 1:" in pii_sanitizer.FEW_SHOT_EXAMPLES
    assert "Input:" in pii_sanitizer.FEW_SHOT_EXAMPLES
    assert "Output:" in pii_sanitizer.FEW_SHOT_EXAMPLES


def test_example_output_is_valid_json_with_expected_schema():
    output = _example_output()

    assert set(output) == {"redacted_text", "entities_found"}
    assert isinstance(output["redacted_text"], str)
    assert isinstance(output["entities_found"], list)
    assert output["entities_found"]

    for entity in output["entities_found"]:
        assert set(entity) == {"type", "original_value"}
        assert isinstance(entity["type"], str)
        assert isinstance(entity["original_value"], str)
        assert entity["type"]
        assert entity["original_value"]


def test_example_entities_match_input_and_redacted_text():
    source = _example_input()
    output = _example_output()
    redacted_text = output["redacted_text"]

    for entity in output["entities_found"]:
        placeholder = f"[{entity['type']}]"
        assert entity["original_value"] in source
        assert entity["original_value"] not in redacted_text
        assert placeholder in redacted_text


def test_example_keeps_current_sensitive_categories():
    output = _example_output()
    entity_types = {entity["type"] for entity in output["entities_found"]}

    assert entity_types == {
        "EMPLOYEE_ID",
        "NAME",
        "SALARY",
        "SSN",
        "BANK_ACCOUNT",
    }


# ============================================================
# REAL FUNCTIONAL TESTS - These actually exercise the skill
# ============================================================


def test_real_sanitize_text_basic_pii():
    """Verify sanitize_text actually redacts real PII using the LLM."""
    sample = "Contact John Doe at john.doe@acme.com or call 555-123-4567. SSN is 987-65-4321."

    result = pii_sanitizer.sanitize_text(sample, multi_pass=2)

    assert "redacted_text" in result
    assert "entities_found" in result
    assert len(result["entities_found"]) >= 3  # at least name, email, phone, ssn

    redacted = result["redacted_text"]
    assert "John Doe" not in redacted
    assert "john.doe@acme.com" not in redacted
    assert "555-123-4567" not in redacted
    assert "987-65-4321" not in redacted

    # Placeholders should appear
    assert "[NAME]" in redacted or any("[NAME" in e["type"] for e in result["entities_found"])
    assert any("EMAIL" in e["type"] for e in result["entities_found"])


def test_real_multi_pass_increases_detection():
    """Confirm multi_pass=3 discovers at least as many entities as single pass."""
    sample = (
        "Patient: Maria Garcia, DOB 03/15/1985, "
        "Policy #HLTH-88421, Employer: TechCorp Inc, "
        "Direct deposit to IBAN DE89 3704 0044 0532 0130 00"
    )

    single = pii_sanitizer.sanitize_text(sample, multi_pass=1)
    multi = pii_sanitizer.sanitize_text(sample, multi_pass=3)

    assert len(multi["entities_found"]) >= len(single["entities_found"])
    assert multi.get("passes_completed", 0) == 3 or len(multi["entities_found"]) > 0


def test_real_sanitize_handles_no_pii():
    """Non-sensitive text should remain unchanged with zero entities."""
    sample = "The quarterly revenue increased by 12 percent this quarter."

    result = pii_sanitizer.sanitize_text(sample, multi_pass=1)

    assert result["redacted_text"] == sample
    assert result["entities_found"] == []


def main():
    checks = [
        test_exports_few_shot_examples,
        test_example_output_is_valid_json_with_expected_schema,
        test_example_entities_match_input_and_redacted_text,
        test_example_keeps_current_sensitive_categories,
        # Real verification tests
        test_real_sanitize_text_basic_pii,
        test_real_multi_pass_increases_detection,
        test_real_sanitize_handles_no_pii,
    ]
    failures = 0

    print("pii-sanitizer FULL VERIFICATION (prompt + live LLM)")
    print("=" * 55)
    for check in checks:
        try:
            check()
        except Exception as exc:
            failures += 1
            print(f"FAIL {check.__name__}: {exc}")
        else:
            print(f"PASS {check.__name__}")

    print("=" * 55)
    if failures:
        print(f"{failures} check(s) failed")
        return 1
    print("All checks passed - skill works correctly")
    return 0


if __name__ == "__main__":
    sys.exit(main())
