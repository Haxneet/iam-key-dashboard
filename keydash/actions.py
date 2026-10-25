"""Write actions. OFF by default.

To turn them on you must start the app with ENABLE_WRITE_ACTIONS=true, and every
action still needs a typed confirmation in the UI. This app never deletes or
deactivates keys.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

import boto3

from .audit import write_audit
from .aws import BOTO_CONFIG, whoami

USER_NAME_RE = re.compile(r"^[\w+=,.@-]{1,64}$")
WRITE_FLAG = "ENABLE_WRITE_ACTIONS"


class ActionNotAllowed(Exception):
    pass


@dataclass(frozen=True, repr=False)
class NewKey:
    account_id: str
    user_name: str
    access_key_id: str
    secret_access_key: str

    def __repr__(self) -> str:
        return f"NewKey(user={self.user_name!r}, access_key_id={self.access_key_id!r}, secret=***)"

    __str__ = __repr__


def write_actions_enabled() -> bool:
    return os.environ.get(WRITE_FLAG, "").strip().lower() == "true"


def expected_confirmation(user_name: str) -> str:
    return f"CREATE {user_name}"


def create_access_key(
    session: boto3.Session,
    account_id: str,
    user_name: str,
    confirmation: str,
    actor_arn: str,
) -> NewKey:
    if not write_actions_enabled():
        raise ActionNotAllowed(f"Write actions are off. Start the app with {WRITE_FLAG}=true.")
    if not USER_NAME_RE.match(user_name):
        raise ActionNotAllowed("That is not a valid IAM user name.")
    if confirmation.strip() != expected_confirmation(user_name):
        raise ActionNotAllowed("Confirmation text does not match. Nothing was changed.")

    # Make sure we are about to change the account we think we are.
    actual_account = whoami(session)["account"]
    if actual_account != account_id:
        raise ActionNotAllowed(
            f"Session is for account {actual_account}, not {account_id}. Nothing was changed."
        )

    iam = session.client("iam", config=BOTO_CONFIG)
    existing = iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]
    if len(existing) >= 2:
        raise ActionNotAllowed(
            "This user already has 2 keys (the AWS maximum). "
            "An old key must be removed first. Nothing was changed."
        )

    write_audit(
        "create_access_key_requested",
        actor=actor_arn,
        account_id=account_id,
        user_name=user_name,
    )
    resp = iam.create_access_key(UserName=user_name)["AccessKey"]
    new_key = NewKey(
        account_id=account_id,
        user_name=user_name,
        access_key_id=resp["AccessKeyId"],
        secret_access_key=resp["SecretAccessKey"],
    )
    write_audit(
        "create_access_key_succeeded",
        actor=actor_arn,
        account_id=account_id,
        user_name=user_name,
        access_key_id=new_key.access_key_id,  # the ID is not secret; the secret is never logged
    )
    return new_key


__all__ = [
    "ActionNotAllowed",
    "NewKey",
    "create_access_key",
    "expected_confirmation",
    "write_actions_enabled",
]
