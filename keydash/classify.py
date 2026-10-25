"""Turns raw key data into statuses and plain-English recommendations.

Pure functions with no AWS calls, so they are easy to test.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .config import Settings

# Age status
AGE_OK = "OK"
AGE_SOON = "Rotate soon"
AGE_DUE = "Needs rotation"

# Old key used within this many days = owner is clearly still switching over.
STILL_SWITCHING_DAYS = 7

# Usage status
USE_ACTIVE = "In use"
USE_STALE = "Not used recently"
USE_NEVER = "Never used"
USE_INACTIVE = "Inactive"


@dataclass
class KeyInfo:
    account_id: str
    account_name: str
    user_name: str
    user_type: str  # "IAM" or "SMTP"
    owner: str  # email from tags, or "" if missing
    key_id: str
    status: str  # "Active" / "Inactive"
    created: datetime
    last_used: datetime | None
    last_used_service: str = ""
    last_used_region: str = ""


def days_between(earlier: datetime | None, now: datetime) -> int | None:
    if earlier is None:
        return None
    if earlier.tzinfo is None:
        earlier = earlier.replace(tzinfo=timezone.utc)
    return max((now - earlier).days, 0)


def age_status(key: KeyInfo, settings: Settings, now: datetime) -> str:
    age = days_between(key.created, now) or 0
    if age >= settings.max_key_age_days:
        return AGE_DUE
    if age >= settings.warn_key_age_days:
        return AGE_SOON
    return AGE_OK


def usage_status(key: KeyInfo, settings: Settings, now: datetime) -> str:
    if key.status != "Active":
        return USE_INACTIVE
    since = days_between(key.last_used, now)
    if since is None:
        return USE_NEVER
    if since <= settings.active_window_days:
        return USE_ACTIVE
    return USE_STALE


def key_row(key: KeyInfo, settings: Settings, now: datetime) -> dict:
    return {
        "Account": key.account_name,
        "Account ID": key.account_id,
        "User": key.user_name,
        "Type": key.user_type,
        "Owner": key.owner or "(no owner tag)",
        "Access key ID": key.key_id,
        "Key status": key.status,
        "Age (days)": days_between(key.created, now),
        "Age status": age_status(key, settings, now),
        "Last used (days ago)": days_between(key.last_used, now),
        "Usage": usage_status(key, settings, now),
        "Last used service": key.last_used_service,
        "Created": key.created.date().isoformat(),
    }


def recommend(keys: list[KeyInfo], settings: Settings, now: datetime) -> tuple[str, str]:
    """Returns (severity, recommendation) for one user's keys.

    severity is one of: "ok", "info", "action".
    """
    keys = sorted(keys, key=lambda k: k.created)
    usage = [usage_status(k, settings, now) for k in keys]
    ages = [age_status(k, settings, now) for k in keys]

    if len(keys) == 1:
        if usage[0] == USE_INACTIVE:
            return "info", "Only key is inactive. Confirm with owner, then it can be deleted."
        if usage[0] in (USE_NEVER, USE_STALE) and ages[0] != AGE_OK:
            return "action", "Old key that is not in use. Ask owner if it is still needed."
        if ages[0] == AGE_DUE:
            return "action", "Key is past the rotation age. Create a new key and send it to owner."
        if ages[0] == AGE_SOON:
            return "info", "Key will need rotation soon."
        return "ok", "Nothing to do."

    old, new = keys[0], keys[-1]
    old_use, new_use = usage[0], usage[-1]
    in_use = {USE_ACTIVE}
    not_in_use = {USE_NEVER, USE_STALE, USE_INACTIVE}

    if new_use in in_use:
        return _old_key_safety(old, settings, now)
    if old_use in in_use and new_use in not_in_use:
        return "action", (
            f"Rotation in progress: new key {new.key_id} has not been used yet. Remind owner."
        )
    return "action", "Neither key is in use. Ask owner if this user is still needed."


def _old_key_safety(old: KeyInfo, settings: Settings, now: datetime) -> tuple[str, str]:
    """New key is in use. Is it safe to deactivate the old one?

    Safety rule: the old key must not have been used for at least
    `safe_to_deactivate_days` (default 30) before it is deactivated.
    """
    safe = settings.safe_to_deactivate_days
    if old.status != "Active":
        return "action", (
            f"Old key {old.key_id} is already inactive and new key is in use. Old key can be deleted."
        )
    old_days = days_between(old.last_used, now)
    if old_days is None:
        return "action", (
            f"Old key {old.key_id} has never been used and new key is in use. "
            "Old key is safe to deactivate."
        )
    if old_days >= safe:
        return "action", (
            f"Old key {old.key_id} not used for {old_days} days and new key is in use. "
            "Old key is safe to deactivate."
        )
    safe_on = (old.last_used + timedelta(days=safe)).date().isoformat()
    wait = safe - old_days
    if old_days <= STILL_SWITCHING_DAYS:
        return "action", (
            f"Both keys are in use (old key {old.key_id} used {old_days} days ago). "
            f"Remind owner to finish switching. Do not deactivate before {safe_on}."
        )
    return "info", (
        f"New key is in use. Old key {old.key_id} was last used {old_days} days ago. "
        f"Wait {wait} more day(s), until {safe_on}, before deactivating."
    )


def user_rows(keys: list[KeyInfo], settings: Settings, now: datetime) -> list[dict]:
    grouped: dict[tuple[str, str], list[KeyInfo]] = defaultdict(list)
    for k in keys:
        grouped[(k.account_id, k.user_name)].append(k)

    rows = []
    for (_acct, _user), user_keys in grouped.items():
        severity, text = recommend(user_keys, settings, now)
        first = user_keys[0]
        oldest_age = max(days_between(k.created, now) or 0 for k in user_keys)
        rows.append(
            {
                "Severity": severity,
                "Account": first.account_name,
                "Account ID": first.account_id,
                "User": first.user_name,
                "Type": first.user_type,
                "Owner": first.owner or "(no owner tag)",
                "Keys": len(user_keys),
                "Oldest key (days)": oldest_age,
                "Recommendation": text,
            }
        )
    order = {"action": 0, "info": 1, "ok": 2}
    rows.sort(key=lambda r: (order[r["Severity"]], -r["Oldest key (days)"]))
    return rows
