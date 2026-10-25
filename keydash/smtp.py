"""Converts an IAM secret access key into an Amazon SES SMTP password.

This is the algorithm published in the Amazon SES developer guide
("Obtaining Amazon SES SMTP credentials"). The result depends on the region.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re

_DATE = "11111111"
_SERVICE = "ses"
_MESSAGE = "SendRawEmail"
_TERMINAL = "aws4_request"
_VERSION = 0x04

REGION_RE = re.compile(r"^[a-z]{2}(-gov)?-[a-z]+-\d$")


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def ses_smtp_password(secret_access_key: str, region: str) -> str:
    if not REGION_RE.match(region):
        raise ValueError("Not a valid AWS region, for example us-east-1.")
    signature = _sign(("AWS4" + secret_access_key).encode("utf-8"), _DATE)
    signature = _sign(signature, region)
    signature = _sign(signature, _SERVICE)
    signature = _sign(signature, _TERMINAL)
    signature = _sign(signature, _MESSAGE)
    return base64.b64encode(bytes([_VERSION]) + signature).decode("utf-8")


def smtp_endpoint(region: str) -> str:
    if not REGION_RE.match(region):
        raise ValueError("Not a valid AWS region, for example us-east-1.")
    return f"email-smtp.{region}.amazonaws.com"


# Regions where Amazon SES offers an SMTP endpoint (common ones; add yours if missing).
SES_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "ca-central-1",
    "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1", "eu-south-1",
    "ap-south-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
    "sa-east-1", "me-south-1", "af-south-1", "il-central-1",
    "us-gov-west-1", "us-gov-east-1",
]
