# IAM permissions this app needs

The app signs in with your credentials, then switches into `role_name` (from `accounts.json`) in each account.

## Read-only (everything the dashboard shows)

The role in each account needs only these actions. AWS managed policies `SecurityAudit` and `ReadOnlyAccess` already include them.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadIamKeys",
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
        "iam:ListUserTags"
      ],
      "Resource": "*"
    }
  ]
}
```

Optional, only if you use the "Find accounts from AWS Organizations" button (management or delegated admin account only): `organizations:ListAccounts`.

Your own identity needs `sts:AssumeRole` on `arn:aws:iam::*:role/<role_name>`.

## Write (only if you turn on ENABLE_WRITE_ACTIONS)

The app can create a key. It never deactivates or deletes keys.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CreateKeysForIamUsers",
      "Effect": "Allow",
      "Action": ["iam:CreateAccessKey"],
      "Resource": "arn:aws:iam::*:user/*"
    }
  ]
}
```

If the role does not have this, the app shows "Access denied" and nothing changes.

## What shows up in CloudTrail

Every role switch uses a session name like `iam-key-dashboard-<your-name>`, so any call the app makes can be traced back to you.
