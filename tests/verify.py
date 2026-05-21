#!/usr/bin/env python3
"""
pii-sanitizer Verification Script
Tests full Presidio-powered PII redaction for text, code, logs, and multimodal (OCR).
"""

import sys
import tempfile
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from pii_sanitizer import PIISanitizer, OCR_AVAILABLE

def print_result(title, result):
    print(f"\n--- {title} ---")
    if result.get("note"):
        print("⚠️  FALLBACK MODE (Presidio not fully active)")
    else:
        print("✅ FULL PRESIDIO MODE")
    print(f"Entities found: {result['stats']['total_entities']}")
    for e in result.get("entities_found", []):
        print(f"  - {e['entity_type']}: {e['text']}")

def main():
    print("=" * 65)
    print("pii-sanitizer Full Verification Suite")
    print("=" * 65)

    sanitizer = PIISanitizer()

    # Test 1: Basic Chinese + English PII
    print("\n[1] Basic Text (Chinese + English PII)")
    text = "联系人：张三，手机号：13800138000，邮箱：test@company.com，身份证：110101199001011234"
    result = sanitizer.sanitize_text(text)
    print_result("Basic Text", result)

    # Test 2: Code snippet sanitization
    print("\n[2] Code Snippet Sanitization")
    code = '''
import os
API_KEY = "sk-1234567890abcdef"
DB_PASSWORD = "SuperSecret123!"
ADMIN_EMAIL = "admin@internal.company"
'''
    result = sanitizer.sanitize_text(code)
    print_result("Python Code", result)

    # Test 3: Log sanitization
    print("\n[3] Log File Sanitization")
    logs = '''
[INFO] 2026-05-21 14:32:01 User login successful - user: zhangsan@corp.com, ip: 10.0.0.45, token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
[WARN] Failed login attempt from 192.168.1.100 for user: 13800138000
'''
    result = sanitizer.sanitize_text(logs)
    print_result("System Logs", result)

    # Test 4: File-based sanitization
    print("\n[4] File I/O Test")
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write("Error report: user 13800138000 reported issue from IP 172.16.0.23")
        temp_in = f.name
    temp_out = temp_in + ".clean"

    result = sanitizer.sanitize_file(temp_in, output_path=temp_out)
    print(f"   Input : {temp_in}")
    print(f"   Output: {result.get('output_file')}")
    print(f"   Entities redacted: {result['stats']['total_entities']}")

    os.unlink(temp_in)
    if os.path.exists(temp_out):
        os.unlink(temp_out)

    # Test 5: Multimodal (Image OCR) - generate PIL image with PII and OCR it
    print("\n[5] Multimodal Test (Image OCR with PIL-generated image)")
    try:
        from PIL import Image, ImageDraw, ImageFont

        # Create an image with PII text rendered on it
        img = Image.new("RGB", (600, 100), color="white")
        draw = ImageDraw.Draw(img)
        # Try to use a system font; fall back to default
        try:
            font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 20)
        except (OSError, IOError):
            font = ImageFont.load_default()
        pii_text = u"Email: zhangsan@corp.cn Phone: 13800138000 ID: 110101199001011234"
        draw.text((10, 10), pii_text, fill="black", font=font)

        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            img.save(f, format="PNG")
            temp_img = f.name

        print(f"   Generated test image: {temp_img}")

        if OCR_AVAILABLE:
            result = sanitizer.sanitize_text("OCR test", image_path=temp_img)
            print_result("Image OCR", result)
        else:
            print("   ⚠️  pytesseract/Pillow not available; OCR test skipped")
            print("   Install with: pip install pytesseract pillow && brew install tesseract tesseract-lang")

        os.unlink(temp_img)
    except ImportError:
        print("   ⚠️  Pillow not available; skipping image generation")

    # Final schema check
    print("\n[6] Output Schema Validation")
    required_keys = ["original_length", "redacted_length", "entities_found", "redacted_text", "stats", "output_file"]
    if all(k in result for k in required_keys):
        print("   ✅ All required keys present in result")
    else:
        print("   ❌ Missing keys detected")

    print("\n" + "=" * 65)
    print("Verification complete.")
    print("=" * 65)

if __name__ == "__main__":
    main()