"""Tests for reminder tracking and email templates. No AWS, no email is sent."""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlparse

from keydash import emails, reminders
from keydash.classify import KeyInfo
from keydash.config import ConfigError, Settings, parse_settings

NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)
S = Settings()


def key(age, used, kid="AKIAOLD"):
    return KeyInfo("111111111111", "prod", "alice", "IAM", "alice@example.com", kid, "Active",
                   NOW - timedelta(days=age), None if used is None else NOW - timedelta(days=used))


class ReminderStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.p = mock.patch.object(reminders, "DATA_DIR", Path(self.tmp.name))
        self.p.start()

    def tearDown(self):
        self.p.stop()
        self.tmp.cleanup()

    def test_defaults(self):
        info = reminders.get("1", "alice")
        self.assertFalse(info["stopped"])
        self.assertEqual(info["history"], [])
        self.assertEqual(reminders.summary("1", "alice"), ("On", ""))

    def test_log_and_stop_resume(self):
        reminders.log_sent("1", "alice", "a@example.com", emails.ROTATE, "me")
        info = reminders.get("1", "alice")
        self.assertEqual(len(info["history"]), 1)
        self.assertEqual(info["email"], "a@example.com")
        reminders.set_stopped("1", "alice", True)
        self.assertEqual(reminders.summary("1", "alice")[0], "Stopped")
        reminders.set_stopped("1", "alice", False)
        self.assertFalse(reminders.get("1", "alice")["stopped"])
        # other users are untouched
        self.assertEqual(reminders.get("1", "bob")["history"], [])

    def test_corrupt_file_is_ignored(self):
        (Path(self.tmp.name) / "reminders.json").write_text("{not json")
        self.assertEqual(reminders.load(), {})


class EmailTests(unittest.TestCase):
    def test_suggested_template(self):
        self.assertEqual(emails.suggested_template([key(120, 1)], S, NOW), emails.ROTATE)
        self.assertEqual(emails.suggested_template([key(200, 150)], S, NOW), emails.UNUSED)
        self.assertEqual(
            emails.suggested_template([key(200, 1), key(5, None, "AKIANEW")], S, NOW), emails.SWITCH
        )

    def test_render_fills_values(self):
        subj, body = emails.render(emails.ROTATE, [key(120, 1)], S, NOW, "Security")
        self.assertIn("alice", subj)
        self.assertIn("120 days old", body)
        self.assertNotIn("{", body)

    def test_new_key_email_has_link_not_secret(self):
        subj, body = emails.render(emails.NEW_KEY, [key(120, 1)], S, NOW, "Security",
                                   lastpass_link="https://lastpass.example/share/abc",
                                   kind="SMTP", smtp_region="us-east-1")
        self.assertIn("https://lastpass.example/share/abc", body)
        self.assertIn("email-smtp.us-east-1.amazonaws.com", body)
        self.assertIn("SMTP", subj)

    def test_gmail_url(self):
        url = emails.gmail_draft_url("a@example.com", "Hi & bye", "line1\nline2", "me@corp.com")
        q = parse_qs(urlparse(url).query)
        self.assertEqual(urlparse(url).netloc, "mail.google.com")
        self.assertEqual(q["to"], ["a@example.com"])
        self.assertEqual(q["su"], ["Hi & bye"])
        self.assertEqual(q["body"], ["line1\nline2"])
        self.assertEqual(q["authuser"], ["me@corp.com"])

    def test_email_validation(self):
        self.assertTrue(emails.is_valid_email("a.b@corp.com"))
        for bad in ("", "(no owner tag)", "a@b", "a@b.com,c@d.com", "a b@c.com"):
            self.assertFalse(emails.is_valid_email(bad), bad)

    def test_config_gmail(self):
        self.assertEqual(parse_settings({"gmail_account": "me@corp.com"}).gmail_account, "me@corp.com")
        with self.assertRaises(ConfigError):
            parse_settings({"gmail_account": "not-an-email"})


if __name__ == "__main__":
    unittest.main()
