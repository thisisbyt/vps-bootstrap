import unittest

from app.safe_logging import redact


class RedactionTests(unittest.TestCase):
    def test_redacts_common_secret_assignments(self) -> None:
        text = redact("password=secret token:abcd token=SECRET private_key = value")

        self.assertNotIn("secret", text)
        self.assertNotIn("abcd", text)
        self.assertNotIn("SECRET", text)
        self.assertNotIn("value", text)
        self.assertIn("[REDACTED]", text)

    def test_redacts_postgres_url_password(self) -> None:
        text = redact("postgresql://user:pass@example/db")

        self.assertNotIn("pass", text)
        self.assertIn("[REDACTED]", text)

    def test_redacts_json_token(self) -> None:
        text = redact('"token": "SECRET"')

        self.assertNotIn("SECRET", text)
        self.assertIn("[REDACTED]", text)

    def test_redacts_authorization_bearer(self) -> None:
        text = redact("Authorization: Bearer SECRET")

        self.assertNotIn("SECRET", text)
        self.assertIn("Bearer [REDACTED]", text)

    def test_redacts_telegram_bot_api_url(self) -> None:
        text = redact("https://api.telegram.org/bot123456:SECRET/sendMessage")

        self.assertNotIn("123456:SECRET", text)
        self.assertIn("[REDACTED]", text)
