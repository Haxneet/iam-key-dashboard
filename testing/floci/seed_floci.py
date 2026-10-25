"""Creates sample IAM users and keys in the local Floci emulator.

Safety: this script refuses to run unless AWS_ENDPOINT_URL points at your own
machine, so it can never create users in a real AWS account.

    export AWS_ENDPOINT_URL=http://localhost:4566
    export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1
    python testing/floci/seed_floci.py
"""

import os
import sys
from urllib.parse import urlparse

import boto3

endpoint = os.environ.get("AWS_ENDPOINT_URL", "")
if urlparse(endpoint).hostname not in ("localhost", "127.0.0.1"):
    sys.exit("Refusing to run: set AWS_ENDPOINT_URL=http://localhost:4566 first.")

iam = boto3.client("iam", endpoint_url=endpoint, region_name="us-east-1")

USERS = {
    # user name: (number of keys, owner email)
    "alice-app": (1, "alice@example.com"),
    "bob-batch": (2, "bob@example.com"),
    "billing-smtp": (1, "ops@example.com"),
    "legacy-no-owner": (1, None),
}

for name, (key_count, owner) in USERS.items():
    try:
        iam.create_user(UserName=name)
    except iam.exceptions.EntityAlreadyExistsException:
        print(f"{name} already exists, skipping")
        continue
    if owner:
        iam.tag_user(UserName=name, Tags=[{"Key": "Owner", "Value": owner}])
    for _ in range(key_count):
        iam.create_access_key(UserName=name)  # fake keys, discarded on purpose
    print(f"created {name} with {key_count} key(s)")

print("Done. In the app, turn on 'Only scan the account I'm signed in to'.")
