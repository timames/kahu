from kahu.clients.redaction import redact_secrets


def test_redacts_password():
    assert "***REDACTED***" in redact_secrets("password=hunter2")


def test_redacts_api_key():
    assert "***REDACTED***" in redact_secrets("api_key=sk-abc123xyz")


def test_redacts_bearer_token():
    result = redact_secrets("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.test")
    assert "eyJ" not in result


def test_redacts_aws_key():
    assert "***AWS_KEY_REDACTED***" in redact_secrets("key=AKIAIOSFODNN7EXAMPLE")


def test_preserves_normal_text():
    normal = "User logged in from 10.0.0.1 at 14:00"
    assert redact_secrets(normal) == normal
