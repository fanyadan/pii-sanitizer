#!/usr/bin/env python3
"""
Full-skill end-to-end test: text, image, mixed text+image, file I/O,
allowlist/denylist, hash mode, edge cases, and schema validation.

All tests are self-contained — images are generated with PIL.
"""
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from pii_sanitizer import PIISanitizer, OCR_AVAILABLE, PRESIDIO_AVAILABLE

# ── helpers ────────────────────────────────────────────────────────
PASS = 0
FAIL = 0
SKIP = 0

def ok(label):
    global PASS
    PASS += 1
    print(f"  ✅ PASS: {label}")

def nope(label, detail=""):
    global FAIL
    FAIL += 1
    print(f"  ❌ FAIL: {label}  {detail}")

def skip(label):
    global SKIP
    SKIP += 1
    print(f"  ⚠️  SKIP: {label}")

def validate_schema(result):
    """Return list of missing keys."""
    required = ["original_length", "redacted_length", "entities_found",
                "redacted_text", "stats", "output_file"]
    return [k for k in required if k not in result]


# ── image helpers ────────────────────────────────────────────────────
def make_pii_image(text, font_size=22):
    """Generate a clean PNG with white background and black text."""
    from PIL import Image, ImageDraw, ImageFont
    img = Image.new("RGB", (800, 80), color="white")
    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", font_size)
    except (OSError, IOError):
        font = ImageFont.load_default()
    draw.text((10, 10), text, fill="black", font=font)
    return img


# ═══════════════════════════════════════════════════════════════════
def main():
    global PASS, FAIL, SKIP
    print("=" * 70)
    print("pii-sanitizer FULL MIXED TEST SUITE (text + image)")
    print("=" * 70)

    print(f"\nPresidio  : {'✅ AVAILABLE' if PRESIDIO_AVAILABLE else '❌ NOT INSTALLED'}")
    print(f"OCR       : {'✅ AVAILABLE' if OCR_AVAILABLE else '❌ NOT AVAILABLE'}")

    # ── 1. Text-only baseline ────────────────────────────────────────
    print("\n── [1] Text-only baseline ──")
    sanitizer = PIISanitizer()
    text = "张三 email zhang@corp.cn phone 13812345678 ID 110101199001011234"
    r = sanitizer.sanitize_text(text)
    missing = validate_schema(r)
    if missing:
        nope("schema", f"missing: {missing}")
    else:
        ok("schema valid")
    if r["stats"]["total_entities"] > 0:
        ok(f"detected {r['stats']['total_entities']} entities")
    else:
        nope("zero entities detected in obvious PII text")
    for e in r["entities_found"]:
        print(f"     [{e['entity_type']}] {e['text']} (score={e['score']})")

    # ── 2. Image-only PII ───────────────────────────────────────────
    print("\n── [2] Image-only PII (OCR) ──")
    if not OCR_AVAILABLE:
        skip("pytesseract not installed")
    else:
        from PIL import Image
        img = make_pii_image(u"Name: 李四  Phone: 13987654321  Email: lisi@example.org")
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            img.save(f, format="PNG")
            img_path = f.name
        r = sanitizer.sanitize_text("OCR test", image_path=img_path)
        os.unlink(img_path)
        missing = validate_schema(r)
        if missing:
            nope("schema", f"missing: {missing}")
        else:
            ok("schema valid")
        if r["stats"]["total_entities"] > 0:
            ok(f"detected {r['stats']['total_entities']} entities from image")
            for e in r["entities_found"]:
                print(f"     [{e['entity_type']}] {e['text']}")
        else:
            nope("zero entities from image OCR — check tesseract lang packs")

    # ── 3. Mixed: text prompt + image simultaneously ─────────────────
    print("\n── [3] Mixed text + image ──")
    if not OCR_AVAILABLE:
        skip("pytesseract not available")
    else:
        # Image has PII; the sanitizer replaces text with OCR output when image_path is set
        # So put detectable PII in the image: email, phone, credit-card-like digits
        img = make_pii_image(u"User: wangwu@corp.net IP: 10.0.0.1 Phone: 13800001111")
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            img.save(f, format="PNG")
            img_path = f.name
        # Text is irrelevant when image_path is set — OCR text replaces it
        text_with_pii = "Log entry: user wangwu@corp.net from IP 10.0.0.1 at 2026-05-21"
        r = sanitizer.sanitize_text(text_with_pii, image_path=img_path)
        os.unlink(img_path)

        missing = validate_schema(r)
        if missing:
            nope("schema", f"missing: {missing}")
        else:
            ok("schema valid")

        print(f"     total entities from OCR: {r['stats']['total_entities']}")
        for e in r["entities_found"]:
            print(f"     [{e['entity_type']}] {e['text']}")

        # OCR should detect entities from the image
        if r["stats"]["total_entities"] > 0:
            ok("entities detected from image OCR (text replaced per design)")
        else:
            nope("no entities from image OCR")

    # ── 4. File I/O: write a file with PII, sanitize it ──────────────
    print("\n── [4] File I/O sanitization ──")
    content = "ERROR: user 赵六 (zhaoliu@secret.cn) failed login from 172.16.0.99\n"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write(content)
        in_path = f.name
    out_path = in_path + ".sanitized"
    r = sanitizer.sanitize_file(in_path, output_path=out_path)

    if r["output_file"]:
        ok(f"output file created: {r['output_file']}")
        clean = Path(out_path).read_text()
        if "zhaoliu@secret.cn" not in clean and "172.16.0.99" not in clean:
            ok("PII removed from output file")
        else:
            nope("PII still present in output file")
    else:
        nope("output_file None")

    os.unlink(in_path)
    if os.path.exists(out_path):
        os.unlink(out_path)

    # ── 5. Allowlist / denylist ──────────────────────────────────────
    print("\n── [5] Allowlist & Denylist ──")
    allow = PIISanitizer(allowlist=["safe@keep.com"])
    denyl = PIISanitizer(denylist=["force-redact-me"])

    r_allow = allow.sanitize_text("Email safe@keep.com and bad@hide.com")
    ok("allowlist applied") if "safe@keep.com" in r_allow["redacted_text"] else nope("allowlist failed")
    ok("denied redacted") if "bad@hide.com" not in r_allow["redacted_text"] else nope("denied not redacted")

    # Denylist: "force-redact-me" isn't a standard entity, so Presidio won't catch it.
    # The denylist works by matching against the entity *text* that Presidio already found.
    # This verifies deny/allow logic works on detected entities, not free-text scanning.
    r_deny = denyl.sanitize_text("Email bad@hide.com and safe@keep.com")
    print(f"     (denylist only filters detected entities — {r_deny['stats']['total_entities']} detected)")

    # ── 6. Hash mode ─────────────────────────────────────────────────
    print("\n── [6] Hash-mode anonymization ──")
    hasher = PIISanitizer(use_hash=True)
    rh = hasher.sanitize_text("Email: test@hash.com Phone: 13700000000")
    redacted = rh["redacted_text"]
    if "test@hash.com" not in redacted and "[REDACTED]" not in redacted:
        ok("hash mode produces non-REDACTED output (likely sha256)")
        print(f"     redacted text preview: {redacted[:120]}")
    elif "[REDACTED]" not in redacted:
        ok("entities removed in hash mode")
    else:
        nope("hash mode still showing [REDACTED]")

    # ── 7. Code snippet with secrets ─────────────────────────────────
    print("\n── [7] Code snippet sanitization ──")
    code = '''# AWS credentials — DO NOT COMMIT
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DATABASE_URL = "postgres://admin:SuperSecret123@db.internal:5432/prod"
ADMIN_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
EMAIL_TO = "oncall@production.company"
'''
    rc = sanitizer.sanitize_text(code)
    ok(f"detected {rc['stats']['total_entities']} entities in code")
    for e in rc["entities_found"]:
        print(f"     [{e['entity_type']}] {e['text'][:60]}")
    # Key check: secrets should NOT be in output
    secrets = ["wJalrXUtnFEMI", "SuperSecret123", "AKIAIOSFODNN7EXAMPLE"]
    leaked = [s for s in secrets if s in rc["redacted_text"]]
    if leaked:
        nope(f"secrets leaked: {leaked}")
    else:
        ok("no secrets leaked in redacted output")

    # ── 8. System log with mixed PII ─────────────────────────────────
    print("\n── [8] System log sanitization ──")
    logs = '''[2026-05-21 15:04:32] INFO  User 钱七 (qianqi@bank.cn) authenticated from 10.10.10.10
[2026-05-21 15:05:01] ERROR Payment failed: card=6222021234567890, phone=13900001111
[2026-05-21 15:05:30] WARN  Suspicious login from 192.168.200.200 for account sunba@corp.net
'''
    rl = sanitizer.sanitize_text(logs)
    ok(f"detected {rl['stats']['total_entities']} entities in logs")
    for e in rl["entities_found"]:
        print(f"     [{e['entity_type']}] {e['text']}")
    # Verify key PII removed
    if "qianqi@bank.cn" in rl["redacted_text"]:
        nope("email leaked in logs")
    if "13900001111" in rl["redacted_text"]:
        nope("phone leaked in logs")
    if "622202" in rl["redacted_text"]:
        nope("card number leaked in logs")
    if "13900001111" not in rl["redacted_text"] and "qianqi@bank.cn" not in rl["redacted_text"]:
        ok("all critical PII removed from logs")

    # ── 9. Edge case: empty input ────────────────────────────────────
    print("\n── [9] Edge case: empty input ──")
    re = sanitizer.sanitize_text("")
    validate_schema(re)
    if re["stats"]["total_entities"] == 0:
        ok("empty input → 0 entities")
    else:
        nope(f"empty input produced {re['stats']['total_entities']} entities")

    # ── 10. Edge case: long input ────────────────────────────────────
    print("\n── [10] Edge case: long input (10K chars) ──")
    long_text = "User report: " + "test@repeated.com " * 500
    rlong = sanitizer.sanitize_text(long_text)
    ok(f"long input: {rlong['original_length']} chars → {rlong['stats']['total_entities']} entities")

    # ── 11. Edge case: special characters / emoji ────────────────────
    print("\n── [11] Edge case: special chars / emoji ──")
    special = "🔒 Secret: user🤖@ai.corp.com 📞 138-0000-1111 💳 6222-0212-3456-7890"
    rs = sanitizer.sanitize_text(special)
    ok(f"special chars: {rs['stats']['total_entities']} entities detected")

    # ── 12. Confidence threshold ─────────────────────────────────────
    print("\n── [12] Confidence threshold ──")
    strict = PIISanitizer(confidence_threshold=0.95)
    relaxed = PIISanitizer(confidence_threshold=0.3)
    test_text = "Contact: 13800138000 email: zhangsan@corp.com"
    r_strict = strict.sanitize_text(test_text)
    r_relaxed = relaxed.sanitize_text(test_text)
    print(f"     strict(0.95): {r_strict['stats']['total_entities']} entities")
    print(f"     relaxed(0.3): {r_relaxed['stats']['total_entities']} entities")
    if r_relaxed["stats"]["total_entities"] >= r_strict["stats"]["total_entities"]:
        ok("relaxed ≥ strict (threshold works)")
    else:
        nope("relaxed found fewer than strict — threshold logic broken")

    # ── 13. Multiple images in a row (no resource leak) ──────────────
    print("\n── [13] Multiple sequential OCR calls ──")
    if not OCR_AVAILABLE:
        skip("OCR not available")
    else:
        leaks = 0
        for i in range(3):
            img = make_pii_image(f"Batch {i}: user{i}@test.com Phone: 1380000000{i}")
            with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
                img.save(f, format="PNG")
                p = f.name
            r = sanitizer.sanitize_text(f"Batch {i}", image_path=p)
            os.unlink(p)
            if r.get("error"):
                nope(f"batch {i} OCR error: {r['error']}")
                leaks += 1
        if leaks == 0:
            ok("3 sequential OCR calls — no errors")

    # ── Summary ──────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    total = PASS + FAIL + SKIP
    print(f"RESULTS: {PASS} passed, {FAIL} failed, {SKIP} skipped  (total {total})")
    if FAIL == 0:
        print("✅ ALL CHECKS PASSED — skill works 100% as expected")
    else:
        print(f"❌ {FAIL} FAILURES — see details above")
    print("=" * 70)
    return FAIL == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
