#!/usr/bin/env python3
"""
pii-sanitizer: Privacy-preserving data redaction using Microsoft Presidio.
Supports text, code, logs, and multimodal (image OCR) inputs.
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

try:
    from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
    from presidio_anonymizer import AnonymizerEngine
    from presidio_anonymizer.entities import RecognizerResult, OperatorConfig
    PRESIDIO_AVAILABLE = True
except ImportError:
    PRESIDIO_AVAILABLE = False

try:
    import pytesseract
    from PIL import Image
    OCR_AVAILABLE = True
except ImportError:
    OCR_AVAILABLE = False


class PIISanitizer:
    def __init__(
        self,
        language: str = "en",
        confidence_threshold: float = 0.6,
        use_hash: bool = False,
        allowlist: Optional[List[str]] = None,
        denylist: Optional[List[str]] = None,
    ):
        self.language = language
        self.confidence_threshold = confidence_threshold
        self.use_hash = use_hash
        self.allowlist = set(allowlist or [])
        self.denylist = set(denylist or [])

        if PRESIDIO_AVAILABLE:
            self.analyzer = AnalyzerEngine()
            self.anonymizer = AnonymizerEngine()
            self._add_chinese_recognizers()
        else:
            self.analyzer = None
            self.anonymizer = None

    def _add_chinese_recognizers(self):
        """Add Chinese phone, ID, bank card, and secret-key recognizers."""
        # Chinese mobile phone
        phone_pattern = Pattern(
            name="chinese_phone",
            regex=r"1[3-9]\d{9}",
            score=0.85,
        )
        phone_recognizer = PatternRecognizer(
            supported_entity="PHONE_NUMBER",
            patterns=[phone_pattern],
            context=["手机", "电话", "联系方式"],
        )
        self.analyzer.registry.add_recognizer(phone_recognizer)

        # Chinese ID card (18 digits)
        id_pattern = Pattern(
            name="chinese_id",
            regex=r"\d{17}[\dXx]",
            score=0.9,
        )
        id_recognizer = PatternRecognizer(
            supported_entity="ID_CARD",
            patterns=[id_pattern],
            context=["身份证", "证件号"],
        )
        self.analyzer.registry.add_recognizer(id_recognizer)

        # Chinese bank card (16-19 digits, typically starts with 62)
        bank_card_pattern = Pattern(
            name="chinese_bank_card",
            regex=r"\b62\d{14,17}\b",
            score=0.85,
        )
        bank_card_recognizer = PatternRecognizer(
            supported_entity="CREDIT_CARD",
            patterns=[bank_card_pattern],
            context=["银行卡", "卡号", "储蓄卡", "信用卡", "card"],
        )
        self.analyzer.registry.add_recognizer(bank_card_recognizer)

        # AWS access key (AKIA...)
        aws_key_pattern = Pattern(
            name="aws_access_key",
            regex=r"\bAKIA[A-Z0-9]{16}\b",
            score=0.95,
        )
        aws_key_recognizer = PatternRecognizer(
            supported_entity="AWS_ACCESS_KEY",
            patterns=[aws_key_pattern],
            context=["AWS", "ACCESS_KEY", "aws_access", "secret"],
        )
        self.analyzer.registry.add_recognizer(aws_key_recognizer)

        # Generic secret / API key (sk- prefix, hex secrets, etc.)
        secret_pattern = Pattern(
            name="api_secret_key",
            regex=r"\b[A-Za-z0-9+/=]{32,64}\b",
            score=0.75,
        )
        secret_recognizer = PatternRecognizer(
            supported_entity="SECRET_KEY",
            patterns=[secret_pattern],
            context=["SECRET", "secret", "password", "token", "key", "API"],
        )
        self.analyzer.registry.add_recognizer(secret_recognizer)

        # Password / credential in assignment (e.g., DB_PASSWORD = "value")
        cred_pattern = Pattern(
            name="credential_value",
            regex=r'''["'][^\n"']{6,128}["']''',
            score=0.8,
        )
        cred_recognizer = PatternRecognizer(
            supported_entity="CREDENTIAL",
            patterns=[cred_pattern],
            context=["PASSWORD", "SECRET", "TOKEN", "API_KEY", "passwd", "credential"],
        )
        self.analyzer.registry.add_recognizer(cred_recognizer)

    def _should_redact(self, text: str, entity_type: str) -> bool:
        if text in self.allowlist:
            return False
        if text in self.denylist:
            return True
        return True

    def sanitize_text(
        self,
        text: str,
        entities: Optional[List[str]] = None,
        image_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Sanitize text or extract + sanitize from image.
        Returns structured result.
        """
        original_text = text

        # Multimodal: OCR from image
        if image_path and OCR_AVAILABLE:
            try:
                img = Image.open(image_path)
                ocr_text = pytesseract.image_to_string(img, lang="eng+chi_sim")
                original_text = ocr_text
                text = ocr_text
            except Exception as e:
                return {"error": f"OCR failed: {e}"}

        if not PRESIDIO_AVAILABLE:
            return {
                "original_length": len(text),
                "redacted_length": len(text),
                "entities_found": [],
                "redacted_text": text,
                "stats": {"total_entities": 0, "by_type": {}},
                "output_file": None,
                "note": "Presidio not installed. Full PII detection disabled. Install with: pip install presidio-analyzer presidio-anonymizer",
            }

        # Analyze
        results = self.analyzer.analyze(
            text=text,
            entities=entities,
            language=self.language,
        )

        # Filter by confidence and allow/deny
        filtered_results = []
        for r in results:
            if r.score < self.confidence_threshold:
                continue
            entity_text = text[r.start : r.end]
            if not self._should_redact(entity_text, r.entity_type):
                continue
            filtered_results.append(r)

        # Anonymize
        if self.use_hash:
            anonymized = self.anonymizer.anonymize(
                text=text,
                analyzer_results=filtered_results,
                operators={"DEFAULT": OperatorConfig("hash", {"hash_type": "sha256"})},
            )
        else:
            anonymized = self.anonymizer.anonymize(
                text=text,
                analyzer_results=filtered_results,
            )

        redacted_text = anonymized.text

        # Build structured output
        entities_found = []
        for r in filtered_results:
            entities_found.append(
                {
                    "entity_type": r.entity_type,
                    "text": text[r.start : r.end],
                    "start": r.start,
                    "end": r.end,
                    "score": round(r.score, 3),
                }
            )

        stats = {}
        for e in entities_found:
            stats[e["entity_type"]] = stats.get(e["entity_type"], 0) + 1

        return {
            "original_length": len(text),
            "redacted_length": len(redacted_text),
            "entities_found": entities_found,
            "redacted_text": redacted_text,
            "stats": {"total_entities": len(entities_found), "by_type": stats},
            "output_file": None,
        }

    def sanitize_file(
        self,
        input_path: Union[str, Path],
        output_path: Optional[Union[str, Path]] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """Sanitize a file and optionally write the result."""
        input_path = Path(input_path)
        content = input_path.read_text(encoding="utf-8", errors="ignore")

        result = self.sanitize_text(content, **kwargs)

        if output_path:
            output_path = Path(output_path)
            output_path.write_text(result["redacted_text"], encoding="utf-8")
            result["output_file"] = str(output_path)

        return result


# Convenience functions
def sanitize_text(text: str, **kwargs) -> Dict[str, Any]:
    return PIISanitizer(**kwargs).sanitize_text(text)


def sanitize_file(input_path: str, output_path: Optional[str] = None, **kwargs) -> Dict[str, Any]:
    return PIISanitizer(**kwargs).sanitize_file(input_path, output_path, **kwargs)


# CLI support
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="PII Sanitizer")
    parser.add_argument("--input", required=True, help="Input file or text")
    parser.add_argument("--output", help="Output file path")
    parser.add_argument("--json", action="store_true", help="Print structured JSON result")
    parser.add_argument("--hash", action="store_true", help="Use hash instead of [REDACTED]")
    args = parser.parse_args()

    sanitizer = PIISanitizer(use_hash=args.hash)

    if Path(args.input).exists():
        result = sanitizer.sanitize_file(args.input, args.output)
    else:
        result = sanitizer.sanitize_text(args.input)

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(result.get("redacted_text", result))