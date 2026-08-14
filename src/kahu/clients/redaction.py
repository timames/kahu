"""Secret redaction — strips known secret patterns before LLM prompt assembly.

Per architecture (Section 4.3): the model never sees raw credentials or secrets.
"""

import re

SECRET_PATTERNS = [
    (re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+"), r"\1=***REDACTED***"),
    (
        re.compile(r"(?i)(api[_-]?key|apikey|token|secret|bearer)\s*[:=]\s*\S+"),
        r"\1=***REDACTED***",
    ),
    (re.compile(r"(?i)authorization:\s*bearer\s+\S+"), "Authorization: Bearer ***REDACTED***"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"), "***EMAIL_REDACTED***"),
    # AWS keys
    (re.compile(r"AKIA[0-9A-Z]{16}"), "***AWS_KEY_REDACTED***"),
    # Private keys
    (
        re.compile(
            r"-----BEGIN\s+(RSA\s+)?PRIVATE KEY-----[\s\S]*?-----END\s+(RSA\s+)?PRIVATE KEY-----"
        ),
        "***PRIVATE_KEY_REDACTED***",
    ),
]


def redact_secrets(text: str) -> str:
    """Apply all redaction patterns to text before it reaches the model."""
    for pattern, replacement in SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text
