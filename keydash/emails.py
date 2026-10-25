"""Email templates and Gmail draft links.

The app never sends email itself. It opens a pre-filled draft in Gmail, and you
review it and press Send. Secrets are never put into an email.
"""

from __future__ import annotations

import re
from datetime import datetime
from urllib.parse import urlencode

from .classify import (
    AGE_OK,
    USE_ACTIVE,
    KeyInfo,
    age_status,
    days_between,
    usage_status,
)
from .config import Settings

EMAIL_RE = re.compile(r"^[^@\s,;]+@[^@\s,;]+\.[^@\s,;]+$")

ROTATE = "Key needs rotation"
UNUSED = "Is this key still needed?"
SWITCH = "Please switch to your new key"
NEW_KEY = "Your new key is ready"

REMINDER_TEMPLATES = (ROTATE, UNUSED, SWITCH)

_TEMPLATES = {
    ROTATE: (
        "Action needed: rotate AWS access key for {user}",
        "Hi,\n\n"
        "The AWS access key {old_key} for IAM user \"{user}\" in account {account} ({account_id}) "
        "is {old_age} days old. Our policy is to rotate access keys every {max_age} days.\n\n"
        "Please reply to this email so we can create a new key for you, "
        "or let us know if this user is no longer needed.\n\n"
        "Thanks,\n{signature}",
    ),
    UNUSED: (
        "Is this AWS access key still needed? ({user})",
        "Hi,\n\n"
        "The AWS access key {old_key} for IAM user \"{user}\" in account {account} ({account_id}) "
        "was last used: {old_last_used}.\n\n"
        "Is this key still needed? If we don't hear back, we may deactivate it.\n\n"
        "Thanks,\n{signature}",
    ),
    SWITCH: (
        "Reminder: switch to your new AWS access key ({user})",
        "Hi,\n\n"
        "A new access key ({new_key}) was created for IAM user \"{user}\" in account "
        "{account} ({account_id}) on {new_created}, but the old key {old_key} is still in use "
        "(last used: {old_last_used}).\n\n"
        "Please update your applications to use the new key and reply once done, "
        "so we can deactivate the old one.\n\n"
        "Thanks,\n{signature}",
    ),
    NEW_KEY: (
        "Your new AWS {kind} credentials for {user}",
        "Hi,\n\n"
        "New {kind} credentials have been created for IAM user \"{user}\" in account "
        "{account} ({account_id}).\n\n"
        "Get them from LastPass here:\n{lastpass_link}\n\n"
        "{smtp_note}"
        "Please update your applications and reply once done. "
        "After that, the old key {old_key} will be deactivated.\n\n"
        "Never share these credentials over email or chat.\n\n"
        "Thanks,\n{signature}",
    ),
}


def is_valid_email(value: str) -> bool:
    return bool(EMAIL_RE.match(value.strip()))


def _fmt_last_used(key: KeyInfo, now: datetime) -> str:
    days = days_between(key.last_used, now)
    if days is None:
        return "never"
    return f"{key.last_used:%Y-%m-%d} ({days} days ago)"


def suggested_template(keys: list[KeyInfo], settings: Settings, now: datetime) -> str:
    keys = sorted(keys, key=lambda k: k.created)
    if len(keys) >= 2 and usage_status(keys[0], settings, now) == USE_ACTIVE:
        return SWITCH
    oldest = keys[0]
    if usage_status(oldest, settings, now) != USE_ACTIVE and age_status(oldest, settings, now) != AGE_OK:
        return UNUSED
    return ROTATE


def render(
    template: str,
    keys: list[KeyInfo],
    settings: Settings,
    now: datetime,
    signature: str,
    lastpass_link: str = "",
    kind: str = "IAM",
    smtp_region: str = "",
) -> tuple[str, str]:
    keys = sorted(keys, key=lambda k: k.created)
    old, new = keys[0], keys[-1]
    smtp_note = ""
    if kind == "SMTP" and smtp_region:
        smtp_note = (
            f"SMTP server: email-smtp.{smtp_region}.amazonaws.com, port 587 (STARTTLS).\n"
            "The SMTP username and password are in the LastPass entry.\n\n"
        )
    values = {
        "user": old.user_name,
        "account": old.account_name,
        "account_id": old.account_id,
        "old_key": old.key_id,
        "old_age": days_between(old.created, now) or 0,
        "old_last_used": _fmt_last_used(old, now),
        "new_key": new.key_id,
        "new_created": f"{new.created:%Y-%m-%d}",
        "max_age": settings.max_key_age_days,
        "signature": signature,
        "lastpass_link": lastpass_link or "(LastPass link)",
        "kind": kind,
        "smtp_note": smtp_note,
    }
    subject, body = _TEMPLATES[template]
    return subject.format(**values), body.format(**values)


def gmail_draft_url(to: str, subject: str, body: str, account: str | None = None) -> str:
    """Link that opens a pre-filled Gmail compose window. Nothing is sent until you click Send."""
    params = {"view": "cm", "fs": "1", "to": to, "su": subject, "body": body}
    if account:
        params["authuser"] = account  # picks your work account if you're signed in to several
    return "https://mail.google.com/mail/?" + urlencode(params)
