"""Local audit log of every write action. Never contains secrets."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

AUDIT_DIR = Path(os.environ.get("KEYDASH_AUDIT_DIR", "logs"))
AUDIT_FILE = "audit.jsonl"
FORBIDDEN_FIELDS = {"secret", "secret_access_key", "session_token", "password", "smtp_password"}


def write_audit(event: str, **fields: str) -> None:
    bad = FORBIDDEN_FIELDS.intersection(k.lower() for k in fields)
    if bad:
        raise ValueError(f"Refusing to write secret fields to the audit log: {sorted(bad)}")

    AUDIT_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = AUDIT_DIR / AUDIT_FILE
    record = {"time": datetime.now(timezone.utc).isoformat(), "event": event, **fields}

    # Create the file readable only by you (on Mac/Linux).
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")
