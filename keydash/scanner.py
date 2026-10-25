"""Read-only scan of IAM users and access keys. Uses only List*/Get* calls."""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable

from botocore.exceptions import BotoCoreError, ClientError

from .aws import BOTO_CONFIG, Credentials, assume_role_session, make_session
from .classify import KeyInfo
from .config import Account, Settings

FRIENDLY_ERRORS = {
    "AccessDenied": "Access denied. Check the role exists and trusts your identity.",
    "AccessDeniedException": "Access denied for this call.",
    "ExpiredToken": "Your credentials have expired. Sign in again.",
    "ExpiredTokenException": "Your credentials have expired. Sign in again.",
    "InvalidClientTokenId": "The access key was not recognised.",
    "SignatureDoesNotMatch": "The secret access key is wrong.",
    "Throttling": "AWS is throttling requests. Try again in a minute.",
}


def friendly_error(exc: Exception) -> str:
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code", "")
        return FRIENDLY_ERRORS.get(code, f"AWS error: {code or 'unknown'}")
    if isinstance(exc, BotoCoreError):
        return f"Connection problem: {type(exc).__name__}"
    return f"Unexpected error: {type(exc).__name__}"


@dataclass
class ScanResult:
    keys: list[KeyInfo] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)  # account label -> message
    users_scanned: int = 0


def _owner_from_tags(tags: list[dict], owner_keys: tuple[str, ...]) -> str:
    by_key = {t["Key"]: t["Value"] for t in tags}
    for k in owner_keys:
        if by_key.get(k):
            return by_key[k][:256]
    return ""


def _user_type(user_name: str, tags: list[dict], pattern: str) -> str:
    if re.search(pattern, user_name, re.IGNORECASE):
        return "SMTP"
    for t in tags:
        if t["Key"].lower() in ("purpose", "type", "usage") and "smtp" in t["Value"].lower():
            return "SMTP"
    return "IAM"


def scan_iam(iam, account: Account, settings: Settings) -> tuple[list[KeyInfo], int]:
    """Scans one account with an IAM client. Returns (keys, number of users)."""
    keys: list[KeyInfo] = []
    users = 0
    for page in iam.get_paginator("list_users").paginate():
        for user in page["Users"]:
            users += 1
            name = user["UserName"]
            key_meta = []
            for kpage in iam.get_paginator("list_access_keys").paginate(UserName=name):
                key_meta.extend(kpage["AccessKeyMetadata"])
            if not key_meta:
                continue

            tags: list[dict] = []
            try:
                for tpage in iam.get_paginator("list_user_tags").paginate(UserName=name):
                    tags.extend(tpage["Tags"])
            except ClientError:
                tags = []  # tags are nice to have, not required

            owner = _owner_from_tags(tags, settings.owner_tag_keys)
            utype = _user_type(name, tags, settings.smtp_name_pattern)

            for meta in key_meta:
                last = iam.get_access_key_last_used(AccessKeyId=meta["AccessKeyId"]).get(
                    "AccessKeyLastUsed", {}
                )
                keys.append(
                    KeyInfo(
                        account_id=account.id,
                        account_name=account.name,
                        user_name=name,
                        user_type=utype,
                        owner=owner,
                        key_id=meta["AccessKeyId"],
                        status=meta["Status"],
                        created=meta["CreateDate"],
                        last_used=last.get("LastUsedDate"),
                        last_used_service=last.get("ServiceName", "") if last.get("LastUsedDate") else "",
                        last_used_region=last.get("Region", "") if last.get("LastUsedDate") else "",
                    )
                )
    return keys, users


def scan_accounts(
    base_creds: Credentials,
    accounts: list[Account],
    settings: Settings,
    caller_arn: str,
    use_current_credentials: bool = False,
    max_workers: int = 5,
    progress: Callable[[int, int], None] | None = None,
) -> ScanResult:
    """Scans many accounts in parallel. One failing account does not stop the rest."""
    result = ScanResult()

    def one(account: Account):
        if use_current_credentials:
            session = make_session(base_creds, settings.region)
        else:
            session = assume_role_session(base_creds, account.id, settings, caller_arn)
        return scan_iam(session.client("iam", config=BOTO_CONFIG), account, settings)

    done = 0
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(one, a): a for a in accounts}
        for fut in as_completed(futures):
            account = futures[fut]
            try:
                keys, users = fut.result()
                result.keys.extend(keys)
                result.users_scanned += users
            except Exception as exc:  # noqa: BLE001 - report per account, keep going
                result.errors[f"{account.name} ({account.id})"] = friendly_error(exc)
            done += 1
            if progress:
                progress(done, len(accounts))
    return result
