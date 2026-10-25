"""Remembers which reminders you have sent and who you've stopped reminding.

Stored in data/reminders.json on your laptop (git-ignored). Contains names,
email addresses and dates only. Never secrets.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

DATA_DIR = Path(os.environ.get("KEYDASH_DATA_DIR", "data"))
STORE_FILE = "reminders.json"
MAX_HISTORY = 50


def user_key(account_id: str, user_name: str) -> str:
    return f"{account_id}/{user_name}"


def _path() -> Path:
    return DATA_DIR / STORE_FILE


def load() -> dict:
    path = _path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def _save(data: dict) -> None:
    DATA_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Write to a temp file then rename, so a crash never leaves a half-written file.
    fd, tmp = tempfile.mkstemp(dir=DATA_DIR, prefix=".reminders-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, _path())
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def get(account_id: str, user_name: str) -> dict:
    entry = load().get(user_key(account_id, user_name), {})
    return {
        "stopped": bool(entry.get("stopped", False)),
        "stopped_at": entry.get("stopped_at"),
        "email": entry.get("email", ""),
        "history": list(entry.get("history", [])),
    }


def _update(account_id: str, user_name: str, change) -> dict:
    data = load()
    k = user_key(account_id, user_name)
    entry = data.get(k, {})
    change(entry)
    data[k] = entry
    _save(data)
    return entry


def log_sent(account_id: str, user_name: str, to: str, template: str, by: str) -> None:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    def change(entry):
        history = entry.get("history", [])
        history.append({"time": now, "to": to, "template": template, "by": by})
        entry["history"] = history[-MAX_HISTORY:]
        entry["email"] = to

    _update(account_id, user_name, change)


def set_stopped(account_id: str, user_name: str, stopped: bool) -> None:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    def change(entry):
        entry["stopped"] = stopped
        entry["stopped_at"] = now if stopped else None

    _update(account_id, user_name, change)


def remember_email(account_id: str, user_name: str, email: str) -> None:
    _update(account_id, user_name, lambda entry: entry.__setitem__("email", email))


def summary(account_id: str, user_name: str) -> tuple[str, str]:
    """Returns (status, last sent date) for the users table."""
    info = get(account_id, user_name)
    status = "Stopped" if info["stopped"] else "On"
    last = info["history"][-1]["time"][:10] if info["history"] else ""
    return status, last
