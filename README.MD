# vvah-test-target

Deliberately vulnerable Flask app for testing VVAH detection accuracy.

**Ground-truth findings (expected):**
- CWE-798 Hardcoded credentials (API_KEY, DB_PASSWORD, JWT_SECRET)
- CWE-89  SQL Injection (`/login`)
- CWE-78  OS Command Injection (`/ping`)
- CWE-502 Insecure Deserialization (`/profile`)
- CWE-22  Path Traversal (`/download`)
- CWE-489 Debug mode enabled

DO NOT DEPLOY. For local security-testing only.
