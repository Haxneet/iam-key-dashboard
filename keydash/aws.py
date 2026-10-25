"""AWS session helpers.

Credentials live only in memory. They are never logged, printed or written to disk,
and their repr() is masked so they cannot leak through error messages or the UI.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

import boto3
from botocore.config import Config

from .config import Settings

BOTO_CONFIG = Config(
    retries={"max_attempts": 5, "mode": "standard"},
    connect_timeout=5,
    read_timeout=30,
    user_agent_extra="iam-key-dashboard",
)

ACCESS_KEY_RE = re.compile(r"^(AKIA|ASIA)[A-Z0-9]{16}$")
ENV_NAMES = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")


def mask(value: str | None, keep: int = 4) -> str:
    if not value:
        return ""
    return value[:keep] + "*" * max(len(value) - keep, 4)


@dataclass(frozen=True, repr=False)
class Credentials:
    access_key_id: str
    secret_access_key: str
    session_token: str | None = None

    def __repr__(self) -> str:  # never show the secret
        return f"Credentials(access_key_id={mask(self.access_key_id)!r}, secret=***)"

    __str__ = __repr__

    @property
    def is_temporary(self) -> bool:
        return bool(self.session_token)


def endpoint_override() -> str | None:
    """Set when testing against a local emulator such as Floci."""
    return os.environ.get("AWS_ENDPOINT_URL") or None


def creds_from_env() -> Credentials | None:
    ak = os.environ.get("AWS_ACCESS_KEY_ID", "").strip()
    sk = os.environ.get("AWS_SECRET_ACCESS_KEY", "").strip()
    token = os.environ.get("AWS_SESSION_TOKEN", "").strip() or None
    if ak and sk:
        return Credentials(ak, sk, token)
    return None


def validate_credentials(creds: Credentials) -> list[str]:
    """Returns a list of problems. Empty list means the format looks right."""
    problems = []
    if endpoint_override():
        # Local emulators accept dummy values like "test".
        return problems
    if not ACCESS_KEY_RE.match(creds.access_key_id):
        problems.append("Access key ID should start with AKIA or ASIA and be 20 characters.")
    if len(creds.secret_access_key) != 40:
        problems.append("Secret access key should be 40 characters.")
    if creds.access_key_id.startswith("ASIA") and not creds.session_token:
        problems.append("Temporary keys (ASIA...) also need the session token.")
    return problems


def make_session(creds: Credentials, region: str) -> boto3.Session:
    return boto3.Session(
        aws_access_key_id=creds.access_key_id,
        aws_secret_access_key=creds.secret_access_key,
        aws_session_token=creds.session_token,
        region_name=region,
    )


def whoami(session: boto3.Session) -> dict:
    ident = session.client("sts", config=BOTO_CONFIG).get_caller_identity()
    return {"account": ident["Account"], "arn": ident["Arn"]}


def partition_from_arn(arn: str) -> str:
    parts = arn.split(":")
    return parts[1] if len(parts) > 1 and parts[1] else "aws"


def role_session_name(caller_arn: str) -> str:
    """Shows up in CloudTrail so every call is traceable to you."""
    who = caller_arn.rsplit("/", 1)[-1]
    who = re.sub(r"[^\w+=,.@-]", "-", who)
    return f"iam-key-dashboard-{who}"[:64]


def assume_role_session(
    base_creds: Credentials, account_id: str, settings: Settings, caller_arn: str
) -> boto3.Session:
    base = make_session(base_creds, settings.region)
    role_arn = (
        f"arn:{partition_from_arn(caller_arn)}:iam::{account_id}:role/{settings.role_name}"
    )
    params = {
        "RoleArn": role_arn,
        "RoleSessionName": role_session_name(caller_arn),
        "DurationSeconds": 3600,
    }
    if settings.external_id:
        params["ExternalId"] = settings.external_id
    resp = base.client("sts", config=BOTO_CONFIG).assume_role(**params)
    c = resp["Credentials"]
    return boto3.Session(
        aws_access_key_id=c["AccessKeyId"],
        aws_secret_access_key=c["SecretAccessKey"],
        aws_session_token=c["SessionToken"],
        region_name=settings.region,
    )


def discover_org_accounts(session: boto3.Session) -> list[dict]:
    """Only works from the management account or a delegated admin account."""
    org = session.client("organizations", config=BOTO_CONFIG)
    out = []
    for page in org.get_paginator("list_accounts").paginate():
        for acct in page["Accounts"]:
            if acct.get("Status") == "ACTIVE":
                out.append({"id": acct["Id"], "name": acct.get("Name", acct["Id"])})
    return out
