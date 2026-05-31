#!/usr/bin/env python3
"""
pii-sanitizer: High-accuracy PII redaction using local LLM (gemma4:26b)
with multi-pass strategy for maximum detection accuracy.
"""

import json
import re
import ollama
from typing import Any

FEW_SHOT_EXAMPLES = """
Example 1:
Input: "Employee ID: EMP-88291, Name: Maria Santos, Salary: $92,500, SSN: 234-56-7890, Bank Account: BR56 1234 5678 9012"
Output: {
  "redacted_text": "Employee ID: [EMPLOYEE_ID], Name: [NAME], Salary: [SALARY], SSN: [SSN], Bank Account: [BANK_ACCOUNT]",
  "entities_found": [
    {"type": "EMPLOYEE_ID", "original_value": "EMP-88291"},
    {"type": "NAME", "original_value": "Maria Santos"},
    {"type": "SALARY", "original_value": "$92,500"},
    {"type": "SSN", "original_value": "234-56-7890"},
    {"type": "BANK_ACCOUNT", "original_value": "BR56 1234 5678 9012"}
  ]
}
"""

SYSTEM_PROMPT = """You are a world-class PII redaction engine. Your ONLY task is to locate every piece of sensitive or personal data and replace it with a precise placeholder.

You must detect:
- Names, titles, honorifics
- National IDs (SSN, passport, driver's license, national ID)
- Medical record numbers, policy numbers, claim IDs
- Financial (IBAN, bank accounts, salaries, credit cards)
- Contact (email, phone, address)
- Dates of birth, employment details

Output ONLY a single valid JSON object:
{
  "redacted_text": "...",
  "entities_found": [{"type": "...", "original_value": "..."}]
}

Rules:
- Be extremely conservative — when in doubt, redact.
- Use specific types like [PASSPORT], [MRN], [POLICY_NUMBER], [IBAN], [SALARY], [DOB], [DRIVER_LICENSE].
- Never leave original PII in the redacted_text.
- If text has no PII, return the original text with empty list.
"""

def _call_llm(prompt: str, model: str = "gemma4:26b") -> str:
    """Call local Ollama model and return the response content."""
    response = ollama.chat(
        model=model,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ],
        options={"temperature": 0.1, "num_predict": 2048}
    )
    return response["message"]["content"].strip()

def _extract_json(text: str) -> dict[str, Any]:
    """Robustly extract the first JSON object from LLM output."""
    # Try direct parse first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Find balanced JSON
    start = text.find("{")
    if start == -1:
        raise ValueError("No JSON object found in LLM response")

    depth = 0
    in_string = False
    escaped = False
    for i in range(start, len(text)):
        char = text[i]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        else:
            if char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    json_str = text[start : i + 1]
                    return json.loads(json_str)

    raise ValueError("Could not parse balanced JSON from LLM output")

def sanitize_text(text: str, multi_pass: int = 3, model: str = "gemma4:26b") -> dict[str, Any]:
    """
    Sanitize text by detecting and redacting PII using local LLM.
    Uses multi-pass strategy (default 3) and merges results for highest recall.
    """
    if not text or not text.strip():
        return {"redacted_text": text, "entities_found": []}

    all_entities: list[dict] = []
    redacted_versions: list[str] = []

    base_prompt = f"{FEW_SHOT_EXAMPLES}\n\nNow process this new input:\nInput: \"{text}\"\nOutput:"

    for attempt in range(multi_pass):
        try:
            raw = _call_llm(base_prompt, model=model)
            result = _extract_json(raw)

            entities = result.get("entities_found", [])
            redacted = result.get("redacted_text", text)

            # Dedup entities by original_value
            seen = {e["original_value"] for e in all_entities}
            for ent in entities:
                if ent.get("original_value") and ent["original_value"] not in seen:
                    all_entities.append(ent)
                    seen.add(ent["original_value"])

            redacted_versions.append(redacted)
        except Exception:
            # On failure, continue to next pass
            continue

    if not all_entities:
        return {"redacted_text": text, "entities_found": []}

    # Final redaction using the union of all discovered entities
    final_redacted = text
    for ent in sorted(all_entities, key=lambda x: -len(x["original_value"])):  # longest first
        placeholder = f"[{ent['type']}]"
        final_redacted = final_redacted.replace(ent["original_value"], placeholder)

    return {
        "redacted_text": final_redacted,
        "entities_found": all_entities,
        "passes_completed": len(redacted_versions)
    }

def sanitize_file(input_path: str, output_path: str | None = None, **kwargs) -> dict[str, Any]:
    """Sanitize a text file."""
    with open(input_path, "r", encoding="utf-8") as f:
        content = f.read()

    result = sanitize_text(content, **kwargs)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(result["redacted_text"])

    return result
