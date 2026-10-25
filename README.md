# IAM Key Dashboard

A small local app that shows IAM access keys across your AWS accounts, flags the ones that need rotation, and tells you what to do about each user.

- **Read-only by default.** Nothing in AWS can change unless you turn on write actions yourself.
- **Runs only on your laptop.** It listens on `127.0.0.1`, so nobody else on the network can open it.
- **Credentials stay in memory.** You type them in (or use environment variables) each time. They are never saved, logged or shown again.

## What you can do

**See the status of every key:** age, last used, and a plain-English recommendation for each user:

| Situation | What the app tells you |
|---|---|
| One key past 180 days, in use | Rotate it |
| One old key, not used | Ask the owner if it's still needed |
| Two keys, new one in use, old one unused for 30+ days | Old key is safe to deactivate |
| Two keys, new one in use, old one used less than 30 days ago | Wait, and shows the date it becomes safe |
| Two keys, both in use | Remind the owner to finish switching |
| Two keys, new one never used | Rotation in progress, remind the owner |

**Act on each user right from their row.** Every user that needs attention has buttons beside them:

- **🔄 Rotate:** opens a pop-up. Choose **IAM** or **SMTP**, type the confirmation, and the new key is created. SMTP users get their SES SMTP password for each region you pick, pre-selected from where they last sent email. Then paste the LastPass share link and open the "your new key is ready" email in Gmail.
- **📧 Remind:** opens a pop-up with a suggested email template you can edit. Click **Open in Gmail**, press Send there, then **I sent it** so the app remembers.
- **🔕 Stop / 🔔 Resume:** stop or restart reminders for that user.

Rotate is greyed out (hover to see why) in read-only mode, or when the user already has 2 keys.

The app never sends email by itself and never puts a secret in an email. Reminder history is kept in `data/reminders.json` on your laptop (git-ignored). Nothing is sent automatically.

## Setup (once)

You need Python 3.10 or newer.

```bash
git clone https://github.com/Haxneet/iam-key-dashboard.git
cd iam-key-dashboard
cp accounts.example.json accounts.json     # Windows: copy accounts.example.json accounts.json
```

Edit `accounts.json`:

- `role_name`: the security role that exists in every account
- `accounts`: the account IDs and friendly names to scan
- `max_key_age_days`, `warn_key_age_days`: your rotation policy
- `active_window_days`: a key counts as "in use" if it was used within this many days
- `safe_to_deactivate_days`: safety rule. An old key is only called "safe to deactivate" after it has gone unused for this many days (default 30)
- `gmail_account`: your work Gmail address, so drafts open in the right Google account
- `email_signature`: how your emails are signed (`\n` makes a new line)

`accounts.json` is git-ignored, so your account list never gets pushed to GitHub.

## Run it

**Mac / Linux**

```bash
./run.sh
```

**Windows (PowerShell)**

```powershell
.\run.ps1
```

The first run creates a virtual environment and installs the packages. Then open http://localhost:8501.

## Using VS Code

1. **File > Open Folder** and pick `iam-key-dashboard`. Install the recommended Python extensions when VS Code asks.
2. Create the virtual environment: `Ctrl+Shift+P` (Mac: `Cmd+Shift+P`) > **Python: Create Environment** > **Venv**, and tick `requirements.txt` so the packages install.
3. Copy `accounts.example.json` to `accounts.json` and edit it.
4. Open **Run and Debug** (the play icon with a bug) and pick a launch option, then press the green play button:
   - **Dashboard (read-only)**: normal use
   - **Dashboard (write actions ON)**: only when you need to create a key
   - **Seed Floci with sample users** and **Dashboard (Floci test mode)**: safe testing against fake local AWS
5. Open http://localhost:8501. You can set breakpoints in the code and they will pause the app.
6. Tests: the **Testing** panel (flask icon) finds and runs them automatically.
7. Git: the **Source Control** panel handles commit, push and pull.

Do not put real AWS credentials in `.vscode/launch.json`. Enter them in the app's sign-in form instead.

## Signing in

The app asks for the three standard AWS values:

- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_SESSION_TOKEN` (needed for temporary credentials)

Either paste them into the sign-in form, or set them as environment variables before starting the app and click **Use environment credentials**. Temporary credentials (for example from your SSO portal's "Command line or programmatic access" page) are strongly recommended. The app warns you if you use long-lived keys.

You are signed out automatically after 1 hour of inactivity, and when you close or refresh the tab.

## Turning on write actions (optional)

Only do this when you actually need to create a key.

```bash
ENABLE_WRITE_ACTIONS=true ./run.sh                      # Mac / Linux
$env:ENABLE_WRITE_ACTIONS="true"; .\run.ps1             # Windows
```

Even then, creating a key requires:

1. Picking the user from the scanned list (users with 2 keys are excluded, since AWS allows at most 2)
2. Typing `CREATE <username>` exactly
3. Ticking "I understand this creates a real key in AWS"

Before creating, the app double-checks it is talking to the right account. The new secret is shown **once**. Store it in LastPass, then click "I've stored it safely" to clear it from the screen. For SMTP users, the app can also convert it into the SES SMTP password for the region you choose.

Every write action is recorded in `logs/audit.jsonl` (who, when, which account, which user, the new key ID). Secrets are never written there.

The app never deactivates or deletes keys.

## Permissions

See [docs/iam-permissions.md](docs/iam-permissions.md). Read-only needs just 4 IAM actions, which `SecurityAudit` already includes.

## Testing safely with Floci (fake local AWS)

Floci (Docker image `hectorvent/floci`) runs a fake AWS on your laptop, so you can try the app without touching real accounts. Requires Docker.

```bash
docker compose -f testing/floci/docker-compose.yml up -d

export AWS_ENDPOINT_URL=http://localhost:4566
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1

python testing/floci/seed_floci.py        # creates sample users and keys
ENABLE_WRITE_ACTIONS=true ./run.sh
```

In the app, click **Use environment credentials**, then turn on **Only scan the account I'm signed in to**. A yellow **TEST MODE** banner confirms you're pointed at the emulator. The seed script refuses to run unless the endpoint is `localhost`.

When you're done testing, **unset `AWS_ENDPOINT_URL`** (or open a new terminal) before using real credentials.

Note: the sample keys are brand new, so they won't show as old. The unit tests cover the old-key logic.

## Running the tests

```bash
python -m unittest discover -s tests -v
```

The tests fake all AWS responses, so they need no credentials. GitHub Actions also runs them on every push, along with `bandit` (security lint) and `pip-audit` (known vulnerable packages).

## Security summary

| Concern | How it's handled |
|---|---|
| Credentials leaking | Kept in memory only, masked in all error messages, cleared on sign out or after 1 hour idle |
| Credentials in Git | `.gitignore` blocks `.env`, `accounts.json`, logs and AWS files. Nothing secret lives in the code |
| Others on the network | App binds to `127.0.0.1` only |
| Accidental changes | Read-only by default, write needs an env flag + typed confirmation + account check |
| Destructive actions | None. The app cannot deactivate or delete keys |
| Traceability | CloudTrail session name `iam-key-dashboard-<you>`, plus a local audit log |
| Dependency vulnerabilities | Version ranges, Dependabot, and `pip-audit` in CI |
| Telemetry | Streamlit usage stats turned off |

## Roadmap

- Email reminders with editable templates
- Automatic 15-day follow-ups with a stop toggle
- Scheduled scans running in AWS (Lambda + EventBridge)
