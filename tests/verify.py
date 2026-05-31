#!/usr/bin/env python3
"""
Smoke verification for the current pii_sanitizer implementation.

The module currently provides few-shot prompt examples used by the local LLM
sanitizer flow. This script validates that the example block remains parseable
and internally consistent.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from pii_sanitizer import FEW_SHOT_EXAMPLES


def extract_output_json():
    label_pos = FEW_SHOT_EXAMPLES.index("Output:")
    start = FEW_SHOT_EXAMPLES.index("{", label_pos)
    depth = 0
    in_string = False
    escaped = False

    for index in range(start, len(FEW_SHOT_EXAMPLES)):
        char = FEW_SHOT_EXAMPLES[index]
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
                return FEW_SHOT_EXAMPLES[start : index + 1]

    raise ValueError("No balanced JSON object found after Output:")


def extract_input_text():
    marker = 'Input: "'
    start = FEW_SHOT_EXAMPLES.index(marker) + len(marker)
    end = FEW_SHOT_EXAMPLES.index('"', start)
    return FEW_SHOT_EXAMPLES[start:end]


def validate_example():
    errors = []
    source = extract_input_text()
    output = json.loads(extract_output_json())
    entities = output.get("entities_found")
    redacted_text = output.get("redacted_text", "")

    if not isinstance(redacted_text, str) or not redacted_text:
        errors.append("redacted_text must be a non-empty string")
    if not isinstance(entities, list) or not entities:
        errors.append("entities_found must be a non-empty list")
        return errors, output

    for index, entity in enumerate(entities, start=1):
        entity_type = entity.get("type")
        original_value = entity.get("original_value")
        if not entity_type or not original_value:
            errors.append(f"entity {index} must include type and original_value")
            continue

        if original_value not in source:
            errors.append(f"{original_value!r} is not present in the example input")
        if original_value in redacted_text:
            errors.append(f"{original_value!r} is still present in redacted_text")
        if f"[{entity_type}]" not in redacted_text:
            errors.append(f"[{entity_type}] placeholder missing from redacted_text")

    return errors, output


def main():
    print("=" * 60)
    print("pii-sanitizer Verification")
    print("=" * 60)
    print("Mode: prompt examples for local-LLM sanitization")

    try:
        errors, output = validate_example()
    except Exception as exc:
        print(f"FAIL: could not parse FEW_SHOT_EXAMPLES: {exc}")
        return 1

    print(f"Entities in example: {len(output['entities_found'])}")
    for entity in output["entities_found"]:
        print(f"  - {entity['type']}: {entity['original_value']}")

    if errors:
        print("\nValidation errors:")
        for error in errors:
            print(f"  - {error}")
        return 1

    print("\nVerification complete: FEW_SHOT_EXAMPLES is valid.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
