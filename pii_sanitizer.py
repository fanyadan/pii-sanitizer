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