from pii_sanitizer import sanitize_text, sanitize_file

# Basic text
result = sanitize_text("联系我：13800138000，邮箱 test@company.com，身份证 110101199001011234")
print(result["redacted_text"])
print(result["stats"])

# File mode
result = sanitize_file("input.log", output_path="sanitized.log")
print("Written to:", result["output_file"])