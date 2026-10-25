"""Loads and validates settings from accounts.json.

accounts.json is git-ignored on purpose. Copy accounts.example.json to get started.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

ACCOUNT_ID_RE = re.compile(r"^\d{12}$")
ROLE_NAME_RE = re.compile(r"^[\w+=,.@-]{1,64}$")
REGION_RE = re.compile(r"^[a-z]{2}(-gov)?-[a-z]+-\d$")
EXTERNAL_ID_RE = re.compile(r"^[\w+=,.@:/-]{2,1224}$")

DEFAULT_CONFIG_PATH = Path("accounts.json")


class ConfigError(ValueError):
    """Raised when accounts.json is missing or invalid."""


@dataclass(frozen=True)
class Account:
    id: str
    name: str


@dataclass
class Settings:
    role_name: str = "SecurityAuditRole"
    external_id: str | None = None
    region: str = "us-east-1"
    max_key_age_days: int = 180
    warn_key_age_days: int = 150
    active_window_days: int = 30
    safe_to_deactivate_days: int = 30
    owner_tag_keys: tuple[str, ...] = ("Owner", "owner", "OwnerEmail", "Email", "email")
    smtp_name_pattern: str = r"smtp|ses"
    gmail_account: str | None = None
    email_signature: str = "Security Team"
    accounts: list[Account] = field(default_factory=list)


def _int_setting(raw: dict, key: str, default: int, low: int, high: int) -> int:
    value = raw.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise ConfigError(f"'{key}' must be a whole number between {low} and {high}.")
    return value


def parse_settings(raw: dict) -> Settings:
    if not isinstance(raw, dict):
        raise ConfigError("accounts.json must contain a JSON object.")

    role_name = raw.get("role_name", Settings.role_name)
    if not isinstance(role_name, str) or not ROLE_NAME_RE.match(role_name):
        raise ConfigError("'role_name' is not a valid IAM role name.")

    external_id = raw.get("external_id")
    if external_id is not None and (
        not isinstance(external_id, str) or not EXTERNAL_ID_RE.match(external_id)
    ):
        raise ConfigError("'external_id' is not valid.")

    region = raw.get("region", Settings.region)
    if not isinstance(region, str) or not REGION_RE.match(region):
        raise ConfigError("'region' is not a valid AWS region, for example us-east-1.")

    max_age = _int_setting(raw, "max_key_age_days", 180, 1, 3650)
    warn_age = _int_setting(raw, "warn_key_age_days", 150, 1, 3650)
    if warn_age > max_age:
        raise ConfigError("'warn_key_age_days' must not be larger than 'max_key_age_days'.")
    active_window = _int_setting(raw, "active_window_days", 30, 1, 365)
    safe_days = _int_setting(raw, "safe_to_deactivate_days", 30, 1, 365)

    owner_tags = raw.get("owner_tag_keys", list(Settings.owner_tag_keys))
    if not isinstance(owner_tags, list) or not all(isinstance(t, str) and t for t in owner_tags):
        raise ConfigError("'owner_tag_keys' must be a list of tag names.")

    smtp_pattern = raw.get("smtp_name_pattern", Settings.smtp_name_pattern)
    try:
        re.compile(smtp_pattern)
    except (re.error, TypeError) as exc:
        raise ConfigError("'smtp_name_pattern' is not a valid regular expression.") from exc

    gmail_account = raw.get("gmail_account") or None
    if gmail_account is not None and (
        not isinstance(gmail_account, str) or not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", gmail_account)
    ):
        raise ConfigError("'gmail_account' must be an email address.")

    signature = raw.get("email_signature", Settings.email_signature)
    if not isinstance(signature, str) or len(signature) > 500:
        raise ConfigError("'email_signature' must be text (500 characters max).")

    accounts: list[Account] = []
    seen: set[str] = set()
    for entry in raw.get("accounts", []):
        if not isinstance(entry, dict):
            raise ConfigError("Each item in 'accounts' must be an object with 'id' and 'name'.")
        acct_id = str(entry.get("id", "")).strip()
        name = str(entry.get("name", acct_id)).strip()[:64] or acct_id
        if not ACCOUNT_ID_RE.match(acct_id):
            raise ConfigError(f"Account id '{acct_id}' must be exactly 12 digits.")
        if acct_id in seen:
            raise ConfigError(f"Account id '{acct_id}' is listed twice.")
        seen.add(acct_id)
        accounts.append(Account(id=acct_id, name=name))

    return Settings(
        role_name=role_name,
        external_id=external_id,
        region=region,
        max_key_age_days=max_age,
        warn_key_age_days=warn_age,
        active_window_days=active_window,
        safe_to_deactivate_days=safe_days,
        owner_tag_keys=tuple(owner_tags),
        smtp_name_pattern=smtp_pattern,
        gmail_account=gmail_account,
        email_signature=signature,
        accounts=accounts,
    )


def load_settings(path: Path = DEFAULT_CONFIG_PATH) -> Settings:
    if not path.exists():
        raise ConfigError(
            f"{path} was not found. Copy accounts.example.json to accounts.json and edit it."
        )
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{path} is not valid JSON (line {exc.lineno}).") from exc
    return parse_settings(raw)
