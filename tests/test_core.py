"""Unit tests. Run with:  python -m unittest discover -s tests -v

No real AWS calls are made. botocore's Stubber fakes the API responses.
"""

from __future__ import annotations

import base64
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import boto3
from botocore.stub import Stubber

from keydash import actions, audit
from keydash.aws import Credentials, role_session_name, validate_credentials
from keydash.classify import (
    AGE_DUE,
    AGE_OK,
    AGE_SOON,
    USE_ACTIVE,
    USE_NEVER,
    USE_STALE,
    KeyInfo,
    age_status,
    recommend,
    usage_status,
    user_rows,
)
from keydash.config import Account, ConfigError, Settings, parse_settings
from keydash.scanner import friendly_error, scan_iam
from keydash.smtp import ses_smtp_password, smtp_endpoint

NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)
SETTINGS = Settings(max_key_age_days=90, warn_key_age_days=75)
FAKE_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def days_ago(n: int | None):
    return None if n is None else NOW - timedelta(days=n)


def key(age: int, used: int | None, status: str = "Active", kid: str = "AKIAOLD") -> KeyInfo:
    return KeyInfo(
        account_id="111111111111",
        account_name="test",
        user_name="alice",
        user_type="IAM",
        owner="alice@example.com",
        key_id=kid,
        status=status,
        created=days_ago(age),
        last_used=days_ago(used),
    )


def iam_client():
    return boto3.client(
        "iam",
        region_name="us-east-1",
        aws_access_key_id="AKIATESTTESTTESTTEST",
        aws_secret_access_key="x" * 40,
    )


class ConfigTests(unittest.TestCase):
    def test_valid(self):
        s = parse_settings({"role_name": "SecurityRole", "accounts": [{"id": "123456789012", "name": "a"}]})
        self.assertEqual(s.accounts, [Account("123456789012", "a")])

    def test_bad_account_id(self):
        with self.assertRaises(ConfigError):
            parse_settings({"accounts": [{"id": "1234"}]})

    def test_duplicate_account(self):
        with self.assertRaises(ConfigError):
            parse_settings({"accounts": [{"id": "123456789012"}, {"id": "123456789012"}]})

    def test_warn_bigger_than_max(self):
        with self.assertRaises(ConfigError):
            parse_settings({"max_key_age_days": 30, "warn_key_age_days": 60})

    def test_defaults_match_policy(self):
        s = parse_settings({})
        self.assertEqual((s.max_key_age_days, s.warn_key_age_days, s.safe_to_deactivate_days), (180, 150, 30))

    def test_bad_role_name(self):
        with self.assertRaises(ConfigError):
            parse_settings({"role_name": "bad role; rm -rf"})


class ClassifyTests(unittest.TestCase):
    def test_age(self):
        self.assertEqual(age_status(key(10, 1), SETTINGS, NOW), AGE_OK)
        self.assertEqual(age_status(key(80, 1), SETTINGS, NOW), AGE_SOON)
        self.assertEqual(age_status(key(120, 1), SETTINGS, NOW), AGE_DUE)

    def test_usage(self):
        self.assertEqual(usage_status(key(10, 1), SETTINGS, NOW), USE_ACTIVE)
        self.assertEqual(usage_status(key(100, 60), SETTINGS, NOW), USE_STALE)
        self.assertEqual(usage_status(key(100, None), SETTINGS, NOW), USE_NEVER)

    def test_one_old_key_in_use(self):
        sev, text = recommend([key(120, 1)], SETTINGS, NOW)
        self.assertEqual(sev, "action")
        self.assertIn("past the rotation age", text)

    def test_one_old_key_unused(self):
        _, text = recommend([key(200, 150)], SETTINGS, NOW)
        self.assertIn("not in use", text)

    def test_two_keys_old_unused_new_used(self):
        _, text = recommend([key(200, 100, kid="AKIAOLD"), key(20, 1, kid="AKIANEW")], SETTINGS, NOW)
        self.assertIn("safe to deactivate", text)
        self.assertIn("AKIAOLD", text)

    def test_two_keys_both_used(self):
        sev, text = recommend([key(200, 1), key(20, 1, kid="AKIANEW")], SETTINGS, NOW)
        self.assertEqual(sev, "action")
        self.assertIn("Both keys are in use", text)
        self.assertIn("Do not deactivate before 2026-10-30", text)

    def test_safety_old_key_used_recently_must_wait(self):
        # old key last used 20 days ago: NOT safe yet, 10 more days to wait
        sev, text = recommend([key(200, 20), key(25, 1, kid="AKIANEW")], SETTINGS, NOW)
        self.assertEqual(sev, "info")
        self.assertNotIn("safe to deactivate", text)
        self.assertIn("Wait 10 more day(s), until 2026-10-11", text)

    def test_safety_boundary_29_vs_30_days(self):
        _, t29 = recommend([key(200, 29), key(40, 1, kid="AKIANEW")], SETTINGS, NOW)
        _, t30 = recommend([key(200, 30), key(40, 1, kid="AKIANEW")], SETTINGS, NOW)
        self.assertNotIn("safe to deactivate", t29)
        self.assertIn("not used for 30 days", t30)
        self.assertIn("safe to deactivate", t30)

    def test_safety_old_key_never_used(self):
        _, text = recommend([key(200, None), key(20, 1, kid="AKIANEW")], SETTINGS, NOW)
        self.assertIn("never been used", text)
        self.assertIn("safe to deactivate", text)

    def test_safety_days_is_configurable(self):
        strict = Settings(max_key_age_days=90, warn_key_age_days=75, safe_to_deactivate_days=60)
        _, text = recommend([key(200, 45), key(50, 1, kid="AKIANEW")], strict, NOW)
        self.assertNotIn("safe to deactivate", text)
        self.assertIn("Wait 15 more day(s)", text)

    def test_two_keys_new_not_used_yet(self):
        _, text = recommend([key(200, 1), key(5, None, kid="AKIANEW")], SETTINGS, NOW)
        self.assertIn("has not been used yet", text)

    def test_two_keys_old_inactive(self):
        _, text = recommend([key(200, 100, status="Inactive"), key(20, 1, kid="AKIANEW")], SETTINGS, NOW)
        self.assertIn("can be deleted", text)

    def test_user_rows_sorted_action_first(self):
        k_ok = key(5, 1)
        k_ok.user_name = "bob"
        rows = user_rows([k_ok, key(200, 1)], SETTINGS, NOW)
        self.assertEqual(rows[0]["User"], "alice")
        self.assertEqual(rows[0]["Severity"], "action")


class ScannerTests(unittest.TestCase):
    def test_scan_one_account(self):
        iam = iam_client()
        created = days_ago(120)
        with Stubber(iam) as stub:
            stub.add_response(
                "list_users",
                {"Users": [
                    {"UserName": "app-smtp", "UserId": "AIDAAAAAAAAAAAAAAAAAA", "Arn": "arn:aws:iam::111111111111:user/app-smtp", "Path": "/", "CreateDate": created},
                    {"UserName": "nokeys", "UserId": "AIDABBBBBBBBBBBBBBBBB", "Arn": "arn:aws:iam::111111111111:user/nokeys", "Path": "/", "CreateDate": created},
                ], "IsTruncated": False},
                {},
            )
            stub.add_response(
                "list_access_keys",
                {"AccessKeyMetadata": [{"UserName": "app-smtp", "AccessKeyId": "AKIAAAAAAAAAAAAAAAAA", "Status": "Active", "CreateDate": created}], "IsTruncated": False},
                {"UserName": "app-smtp"},
            )
            stub.add_response(
                "list_user_tags",
                {"Tags": [{"Key": "Owner", "Value": "dev@example.com"}], "IsTruncated": False},
                {"UserName": "app-smtp"},
            )
            stub.add_response(
                "get_access_key_last_used",
                {"UserName": "app-smtp", "AccessKeyLastUsed": {"LastUsedDate": days_ago(2), "ServiceName": "ses", "Region": "us-east-1"}},
                {"AccessKeyId": "AKIAAAAAAAAAAAAAAAAA"},
            )
            stub.add_response(
                "list_access_keys", {"AccessKeyMetadata": [], "IsTruncated": False}, {"UserName": "nokeys"}
            )
            keys, users = scan_iam(iam, Account("111111111111", "prod"), SETTINGS)
            stub.assert_no_pending_responses()

        self.assertEqual(users, 2)
        self.assertEqual(len(keys), 1)
        k = keys[0]
        self.assertEqual(k.user_type, "SMTP")
        self.assertEqual(k.owner, "dev@example.com")
        self.assertEqual(k.last_used_service, "ses")

    def test_never_used_key(self):
        iam = iam_client()
        with Stubber(iam) as stub:
            stub.add_response("list_users", {"Users": [{"UserName": "bob", "UserId": "AIDACCCCCCCCCCCCCCCCC", "Arn": "arn:aws:iam::111111111111:user/bob", "Path": "/", "CreateDate": NOW}], "IsTruncated": False}, {})
            stub.add_response("list_access_keys", {"AccessKeyMetadata": [{"UserName": "bob", "AccessKeyId": "AKIABBBBBBBBBBBBBBBB", "Status": "Active", "CreateDate": NOW}], "IsTruncated": False}, {"UserName": "bob"})
            stub.add_client_error("list_user_tags", "AccessDenied")
            stub.add_response("get_access_key_last_used", {"UserName": "bob", "AccessKeyLastUsed": {"ServiceName": "N/A", "Region": "N/A"}}, {"AccessKeyId": "AKIABBBBBBBBBBBBBBBB"})
            keys, _ = scan_iam(iam, Account("111111111111", "prod"), SETTINGS)
        self.assertIsNone(keys[0].last_used)
        self.assertEqual(keys[0].owner, "")
        self.assertEqual(keys[0].last_used_service, "")

    def test_friendly_error(self):
        from botocore.exceptions import ClientError

        err = ClientError({"Error": {"Code": "ExpiredToken", "Message": "x"}}, "AssumeRole")
        self.assertIn("expired", friendly_error(err))


class FakeSession:
    def __init__(self, clients):
        self.clients = clients

    def client(self, name, **_):
        return self.clients[name]


class ActionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.audit_patch = mock.patch.object(audit, "AUDIT_DIR", Path(self.tmp.name))
        self.audit_patch.start()

    def tearDown(self):
        self.audit_patch.stop()
        self.tmp.cleanup()

    def _session(self, keys_existing: int, account="111111111111"):
        iam = iam_client()
        sts = boto3.client("sts", region_name="us-east-1", aws_access_key_id="AKIATESTTESTTESTTEST", aws_secret_access_key="x" * 40)
        sts_stub, iam_stub = Stubber(sts), Stubber(iam)
        sts_stub.add_response("get_caller_identity", {"Account": account, "Arn": "arn:aws:sts::1:assumed-role/r/me", "UserId": "AROAX:me"}, {})
        meta = [{"UserName": "alice", "AccessKeyId": f"AKIAEXISTING{i:08d}", "Status": "Active", "CreateDate": NOW} for i in range(keys_existing)]
        iam_stub.add_response("list_access_keys", {"AccessKeyMetadata": meta, "IsTruncated": False}, {"UserName": "alice"})
        if keys_existing < 2:
            iam_stub.add_response(
                "create_access_key",
                {"AccessKey": {"UserName": "alice", "AccessKeyId": "AKIANEWNEWNEWNEWNEW1", "Status": "Active", "SecretAccessKey": FAKE_SECRET, "CreateDate": NOW}},
                {"UserName": "alice"},
            )
        sts_stub.activate()
        iam_stub.activate()
        return FakeSession({"iam": iam, "sts": sts})

    def test_blocked_when_flag_off(self):
        with mock.patch.dict(os.environ, {"ENABLE_WRITE_ACTIONS": ""}):
            with self.assertRaises(actions.ActionNotAllowed):
                actions.create_access_key(None, "111111111111", "alice", "CREATE alice", "me")

    def test_blocked_on_wrong_confirmation(self):
        with mock.patch.dict(os.environ, {"ENABLE_WRITE_ACTIONS": "true"}):
            with self.assertRaises(actions.ActionNotAllowed):
                actions.create_access_key(None, "111111111111", "alice", "CREATE bob", "me")

    def test_blocked_on_wrong_account(self):
        with mock.patch.dict(os.environ, {"ENABLE_WRITE_ACTIONS": "true"}):
            with self.assertRaises(actions.ActionNotAllowed):
                actions.create_access_key(self._session(1, account="999999999999"), "111111111111", "alice", "CREATE alice", "me")

    def test_blocked_when_two_keys(self):
        with mock.patch.dict(os.environ, {"ENABLE_WRITE_ACTIONS": "true"}):
            with self.assertRaises(actions.ActionNotAllowed):
                actions.create_access_key(self._session(2), "111111111111", "alice", "CREATE alice", "me")

    def test_create_and_audit_has_no_secret(self):
        with mock.patch.dict(os.environ, {"ENABLE_WRITE_ACTIONS": "true"}):
            new = actions.create_access_key(self._session(1), "111111111111", "alice", "CREATE alice", "me")
        self.assertEqual(new.access_key_id, "AKIANEWNEWNEWNEWNEW1")
        self.assertNotIn(FAKE_SECRET, repr(new))
        log = (Path(self.tmp.name) / "audit.jsonl").read_text()
        self.assertIn("AKIANEWNEWNEWNEWNEW1", log)
        self.assertNotIn(FAKE_SECRET, log)

    def test_audit_refuses_secret_fields(self):
        with self.assertRaises(ValueError):
            audit.write_audit("x", secret_access_key="nope")


class AwsHelperTests(unittest.TestCase):
    def test_credentials_repr_hides_secret(self):
        c = Credentials("AKIAIOSFODNN7EXAMPLE", FAKE_SECRET, "token")
        self.assertNotIn(FAKE_SECRET, repr(c))
        self.assertNotIn(FAKE_SECRET, str(c))
        self.assertNotIn("token", repr(c))

    def test_validate_credentials(self):
        with mock.patch.dict(os.environ, {"AWS_ENDPOINT_URL": ""}):
            self.assertEqual(validate_credentials(Credentials("AKIAIOSFODNN7EXAMPLE", FAKE_SECRET)), [])
            self.assertTrue(validate_credentials(Credentials("bad", "short")))
            self.assertTrue(validate_credentials(Credentials("ASIAIOSFODNN7EXAMPLE", FAKE_SECRET)))

    def test_role_session_name(self):
        name = role_session_name("arn:aws:sts::1:assumed-role/AWSReservedSSO_Sec/harneet@example.com")
        self.assertTrue(name.startswith("iam-key-dashboard-"))
        self.assertLessEqual(len(name), 64)


class SmtpTests(unittest.TestCase):
    def test_password_format(self):
        pw = ses_smtp_password(FAKE_SECRET, "us-east-1")
        raw = base64.b64decode(pw)
        self.assertEqual(len(raw), 33)
        self.assertEqual(raw[0], 4)
        self.assertNotEqual(pw, ses_smtp_password(FAKE_SECRET, "eu-west-1"))

    def test_bad_region(self):
        with self.assertRaises(ValueError):
            ses_smtp_password(FAKE_SECRET, "not a region")
        self.assertEqual(smtp_endpoint("us-east-1"), "email-smtp.us-east-1.amazonaws.com")


if __name__ == "__main__":
    unittest.main()
