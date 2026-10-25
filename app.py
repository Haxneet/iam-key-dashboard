"""IAM Key Dashboard (Streamlit).

Run with:  streamlit run app.py
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

import pandas as pd
import streamlit as st

from keydash.actions import (
    ActionNotAllowed,
    create_access_key,
    expected_confirmation,
    write_actions_enabled,
)
from keydash.aws import (
    Credentials,
    assume_role_session,
    creds_from_env,
    discover_org_accounts,
    endpoint_override,
    make_session,
    mask,
    validate_credentials,
    whoami,
)
from keydash import reminders
from keydash.classify import AGE_DUE, AGE_SOON, USE_NEVER, key_row, user_rows
from keydash.emails import (
    NEW_KEY,
    REMINDER_TEMPLATES,
    gmail_draft_url,
    is_valid_email,
    render,
    suggested_template,
)
from keydash.config import Account, ConfigError, load_settings
from keydash.scanner import friendly_error, scan_accounts
from keydash.smtp import SES_REGIONS, ses_smtp_password, smtp_endpoint

IDLE_TIMEOUT_SECONDS = 60 * 60  # sign out after 1 hour of no activity

st.set_page_config(page_title="IAM Key Dashboard", page_icon="🔑", layout="wide")


# ---------------------------------------------------------------- session helpers
def sign_out(reason: str | None = None) -> None:
    for key in ("creds", "caller", "scan", "new_key", "org_accounts"):
        st.session_state.pop(key, None)
    if reason:
        st.session_state["signout_reason"] = reason


def touch() -> None:
    last = st.session_state.get("last_active")
    now = time.time()
    if st.session_state.get("creds") and last and now - last > IDLE_TIMEOUT_SECONDS:
        sign_out("You were signed out after 1 hour of inactivity.")
    st.session_state["last_active"] = now


def try_sign_in(creds: Credentials, region: str) -> None:
    problems = validate_credentials(creds)
    if problems:
        for p in problems:
            st.sidebar.error(p)
        return
    try:
        caller = whoami(make_session(creds, region))
    except Exception as exc:  # noqa: BLE001
        st.sidebar.error(f"Sign in failed. {friendly_error(exc)}")
        return
    st.session_state["creds"] = creds
    st.session_state["caller"] = caller
    st.session_state.pop("signout_reason", None)
    st.rerun()


# ---------------------------------------------------------------- load settings
touch()

try:
    settings = load_settings()
except ConfigError as exc:
    st.title("🔑 IAM Key Dashboard")
    st.error(str(exc))
    st.code("cp accounts.example.json accounts.json", language="bash")
    st.stop()

# ---------------------------------------------------------------- sidebar: sign in
st.sidebar.title("🔑 IAM Key Dashboard")

if endpoint_override():
    st.sidebar.warning(f"TEST MODE: all AWS calls go to {endpoint_override()}")

if reason := st.session_state.get("signout_reason"):
    st.sidebar.info(reason)

if "creds" not in st.session_state:
    st.sidebar.subheader("Sign in")
    st.sidebar.caption(
        "Credentials stay in this app's memory only. They are never saved to disk or logged. "
        "Use temporary credentials (ASIA... with a session token) when you can."
    )

    env_creds = creds_from_env()
    if env_creds:
        st.sidebar.success(f"Found AWS credentials in environment: {mask(env_creds.access_key_id)}")
        if st.sidebar.button("Use environment credentials", type="primary"):
            try_sign_in(env_creds, settings.region)
        st.sidebar.markdown("**or enter them below**")

    with st.sidebar.form("signin", clear_on_submit=True):
        ak = st.text_input("AWS_ACCESS_KEY_ID", type="password", autocomplete="off")
        sk = st.text_input("AWS_SECRET_ACCESS_KEY", type="password", autocomplete="off")
        tok = st.text_input(
            "AWS_SESSION_TOKEN (needed for temporary keys)", type="password", autocomplete="off"
        )
        submitted = st.form_submit_button("Sign in")
    if submitted:
        if not ak or not sk:
            st.sidebar.error("Access key ID and secret access key are required.")
        else:
            try_sign_in(Credentials(ak.strip(), sk.strip(), tok.strip() or None), settings.region)

    st.title("IAM Key Dashboard")
    st.info("Sign in on the left to start. This app is read-only unless you turn on write actions.")
    st.stop()

creds: Credentials = st.session_state["creds"]
caller: dict = st.session_state["caller"]

st.sidebar.success(f"Signed in as\n\n`{caller['arn']}`")
if not creds.is_temporary:
    st.sidebar.warning("You are using long-lived keys. Temporary credentials are safer.")
if st.sidebar.button("Sign out"):
    sign_out("Signed out.")
    st.rerun()

# ---------------------------------------------------------------- sidebar: accounts
st.sidebar.divider()
st.sidebar.subheader("Accounts")
only_current = st.sidebar.toggle(
    "Only scan the account I'm signed in to",
    value=False,
    help="Uses your credentials directly, no role switch. Handy for testing.",
)

if only_current:
    accounts = [Account(id=caller["account"], name="current account")]
else:
    accounts = list(settings.accounts)
    if st.sidebar.button("Find accounts from AWS Organizations"):
        try:
            st.session_state["org_accounts"] = discover_org_accounts(
                make_session(creds, settings.region)
            )
        except Exception as exc:  # noqa: BLE001
            st.sidebar.error(f"Could not list accounts. {friendly_error(exc)}")
    if org := st.session_state.get("org_accounts"):
        known = {a.id for a in accounts}
        accounts += [Account(o["id"], o["name"]) for o in org if o["id"] not in known]

    if not accounts:
        st.sidebar.warning("No accounts listed in accounts.json.")
    else:
        names = [f"{a.name} ({a.id})" for a in accounts]
        picked = st.sidebar.multiselect("Accounts to scan", names, default=names)
        accounts = [a for a, n in zip(accounts, names) if n in picked]
    st.sidebar.caption(f"Role used in each account: `{settings.role_name}`")

# ---------------------------------------------------------------- main: scan
st.title("IAM Key Dashboard")
st.caption(
    f"Rotation age: {settings.max_key_age_days} days · warning at {settings.warn_key_age_days} days · "
    f"'in use' means used in the last {settings.active_window_days} days"
)

if st.button(f"Scan {len(accounts)} account(s)", type="primary", disabled=not accounts):
    bar = st.progress(0.0, text="Scanning...")
    result = scan_accounts(
        creds,
        accounts,
        settings,
        caller["arn"],
        use_current_credentials=only_current,
        progress=lambda d, t: bar.progress(d / t, text=f"Scanned {d} of {t} accounts"),
    )
    bar.empty()
    st.session_state["scan"] = {"result": result, "at": datetime.now(timezone.utc)}

scan = st.session_state.get("scan")
if not scan:
    st.info("Press **Scan** to load access keys.")
    st.stop()

result = scan["result"]
now = datetime.now(timezone.utc)
skipped = f" · {len(result.errors)} account(s) skipped" if result.errors else ""
st.caption(
    f"Last scan: {scan['at']:%Y-%m-%d %H:%M} UTC · {result.users_scanned} users checked{skipped}"
)
if result.errors:
    # Collapsed on purpose: you only need this when an account you expected is missing.
    with st.expander("Which accounts were skipped?", expanded=False):
        for acct, msg in sorted(result.errors.items()):
            st.write(f"**{acct}**: {msg}")

if not result.keys:
    st.success("No access keys found in the scanned accounts.")
    st.stop()

keys_df = pd.DataFrame([key_row(k, settings, now) for k in result.keys])
users_df = pd.DataFrame(user_rows(result.keys, settings, now))

keys_by_user: dict[tuple[str, str], list] = {}
for k in result.keys:
    keys_by_user.setdefault((k.account_id, k.user_name), []).append(k)


def smtp_regions_for(user_keys) -> list[str]:
    """Regions where this user's keys were last used for SES. Good default for SMTP."""
    found = sorted({k.last_used_region for k in user_keys if k.last_used_service == "ses" and k.last_used_region})
    return found or [settings.region]


# ================================================================ pop-up: rotate
@st.dialog("Rotate key", width="large")
def rotate_dialog(account_id: str, user_name: str) -> None:
    row = users_df[(users_df["Account ID"] == account_id) & (users_df["User"] == user_name)].iloc[0]
    user_keys = keys_by_user[(account_id, user_name)]
    new_key = st.session_state.get("new_key")

    # ---- step 2: key was created, hand it over
    if new_key and (new_key.account_id, new_key.user_name) == (account_id, user_name):
        kind = st.session_state.get("new_key_kind", "IAM")
        regions = st.session_state.get("new_key_regions", [settings.region])
        st.success(f"New {kind} credentials created for **{user_name}**.")
        st.warning("Shown only until you clear them. Save them in LastPass now. Never paste them into email or chat.")
        if kind == "SMTP":
            st.text_input("SMTP username", new_key.access_key_id, disabled=True)
            for region in regions:
                st.text_input(
                    f"SMTP password ({region})",
                    ses_smtp_password(new_key.secret_access_key, region),
                    type="password",
                )
                st.caption(f"Server: {smtp_endpoint(region)} · port 587 (STARTTLS)")
        else:
            st.text_input("Access key ID", new_key.access_key_id, disabled=True)
            st.text_input("Secret access key", new_key.secret_access_key, type="password")

        st.markdown("**Send it to the owner**")
        lp = st.text_input("LastPass share link")
        to = st.text_input("Send to", value=default_email(row))
        if lp and is_valid_email(to):
            subj, body = render(
                NEW_KEY, user_keys, settings, now, settings.email_signature,
                lastpass_link=lp, kind=kind, smtp_region=regions[0],
            )
            c1, c2 = st.columns(2)
            c1.link_button("Open email in Gmail", gmail_draft_url(to, subj, body, settings.gmail_account))
            if c2.button("I sent it, log it"):
                reminders.log_sent(account_id, user_name, to, NEW_KEY, caller["arn"])
                st.toast("Logged.")
        if st.button("Done. Clear the secret from the screen.", type="primary"):
            for k in ("new_key", "new_key_kind", "new_key_regions"):
                st.session_state.pop(k, None)
            st.rerun()
        return

    # ---- step 1: confirm and create
    kind = st.radio(
        "Key type", ["IAM", "SMTP"], index=1 if row["Type"] == "SMTP" else 0, horizontal=True
    )
    regions = [settings.region]
    if kind == "SMTP":
        regions = st.multiselect(
            "SES region(s) to make SMTP passwords for",
            sorted(set(SES_REGIONS) | set(smtp_regions_for(user_keys))),
            default=smtp_regions_for(user_keys),
            help="Pre-selected from where this user last sent email.",
        )
    st.markdown(
        f"Creates a **new {kind} key** for **{user_name}** in **{row['Account']}** ({account_id}). "
        "The existing key keeps working until you remove it."
    )
    needed = expected_confirmation(user_name)
    typed = st.text_input(f"Type `{needed}` to confirm")
    if st.button(f"Create new {kind} key", type="primary", disabled=typed.strip() != needed or not regions):
        try:
            session = (
                make_session(creds, settings.region)
                if only_current
                else assume_role_session(creds, account_id, settings, caller["arn"])
            )
            created = create_access_key(session, account_id, user_name, typed, caller["arn"])
        except ActionNotAllowed as exc:
            st.error(str(exc))
            return
        except Exception as exc:  # noqa: BLE001
            st.error(f"Key was not created. {friendly_error(exc)}")
            return
        st.session_state["new_key"] = created
        st.session_state["new_key_kind"] = kind
        st.session_state["new_key_regions"] = regions
        st.rerun(scope="fragment")


# ================================================================ pop-up: reminder
@st.dialog("Send reminder", width="large")
def remind_dialog(account_id: str, user_name: str) -> None:
    row = users_df[(users_df["Account ID"] == account_id) & (users_df["User"] == user_name)].iloc[0]
    user_keys = keys_by_user[(account_id, user_name)]
    info = reminders.get(account_id, user_name)
    if info["history"]:
        st.caption(f"Last reminder: {info['history'][-1]['time'][:10]} · {len(info['history'])} sent in total")

    to = st.text_input("Send to", value=default_email(row))
    suggested = suggested_template(user_keys, settings, now)
    template = st.selectbox("Template", REMINDER_TEMPLATES, index=REMINDER_TEMPLATES.index(suggested))
    subj, body = render(template, user_keys, settings, now, settings.email_signature)
    subj = st.text_input("Subject", value=subj, key=f"subj-{template}")
    body = st.text_area("Message", value=body, height=240, key=f"body-{template}")

    if not is_valid_email(to):
        st.warning("Enter the owner's email address.")
        return
    c1, c2 = st.columns(2)
    c1.link_button("1. Open in Gmail", gmail_draft_url(to, subj, body, settings.gmail_account), type="primary")
    if c2.button("2. I sent it, log it"):
        reminders.log_sent(account_id, user_name, to, template, caller["arn"])
        st.rerun()

    if info["history"]:
        with st.expander("History"):
            st.dataframe(
                pd.DataFrame(info["history"][::-1]).rename(
                    columns={"time": "Sent (UTC)", "to": "To", "template": "Template", "by": "By"}
                ),
                hide_index=True,
            )


def default_email(row) -> str:
    if is_valid_email(row["Owner"]):
        return row["Owner"]
    return reminders.get(row["Account ID"], row["User"])["email"]


# ================================================================ summary
c1, c2, c3, c4 = st.columns(4)
c1.metric("Users needing action", int((users_df["Severity"] == "action").sum()))
c2.metric("Keys past rotation age", int((keys_df["Age status"] == AGE_DUE).sum()))
c3.metric("Users with 2 keys", int((users_df["Keys"] == 2).sum()))
c4.metric("Never-used keys", int((keys_df["Usage"] == USE_NEVER).sum()))

# A created key that hasn't been cleared yet: make it impossible to forget.
if pending := st.session_state.get("new_key"):
    b1, b2 = st.columns([4, 1])
    b1.warning(f"A new key for **{pending.user_name}** is still on screen. Finish handing it over and clear it.")
    if b2.button("Open it"):
        rotate_dialog(pending.account_id, pending.user_name)

# ================================================================ user rows with actions
f1, f2, f3 = st.columns([2, 2, 1])
search = f1.text_input("Search user or owner", placeholder="Search...", label_visibility="collapsed")
acct_filter = f2.multiselect(
    "Accounts", sorted(users_df["Account"].unique()), placeholder="All accounts", label_visibility="collapsed"
)
show_all = f3.toggle("Show all users")

view = users_df if show_all else users_df[users_df["Severity"] != "ok"]
if acct_filter:
    view = view[view["Account"].isin(acct_filter)]
if search:
    s_ = search.lower()
    view = view[
        view["User"].str.lower().str.contains(s_, regex=False)
        | view["Owner"].str.lower().str.contains(s_, regex=False)
    ]

if view.empty:
    st.success("Nothing needs attention. 🎉")

BADGE = {"action": "🔴", "info": "🟡", "ok": "🟢"}
for _, r in view.iterrows():
    acct, user = r["Account ID"], r["User"]
    ukeys = keys_by_user[(acct, user)]
    rem = reminders.get(acct, user)
    with st.container(border=True):
        info_col, status_col, act_col = st.columns([3, 4, 3], vertical_alignment="center")

        type_tag = " · `SMTP`" if r["Type"] == "SMTP" else ""
        info_col.markdown(f"{BADGE[r['Severity']]} **{user}**{type_tag}")
        info_col.caption(f"{r['Account']} ({acct}) · {r['Owner']}")

        key_bits = []
        for k in sorted(ukeys, key=lambda k: k.created):
            age = (now - k.created).days
            used = "never used" if k.last_used is None else f"used {(now - k.last_used).days}d ago"
            key_bits.append(f"`…{k.key_id[-4:]}` {age}d old, {used}" + ("" if k.status == "Active" else " (inactive)"))
        status_col.markdown(r["Recommendation"])
        status_col.caption(" · ".join(key_bits))
        if rem["stopped"]:
            status_col.caption("🔕 Reminders stopped")
        elif rem["history"]:
            status_col.caption(f"📧 Last reminder {rem['history'][-1]['time'][:10]} ({len(rem['history'])} sent)")

        a1, a2, a3 = act_col.columns(3)
        can_rotate = write_actions_enabled() and int(r["Keys"]) < 2
        why_not = (
            "Read-only mode. Start with ENABLE_WRITE_ACTIONS=true to rotate."
            if not write_actions_enabled()
            else "Already has 2 keys (AWS maximum). Remove the old key in the AWS console first."
            if int(r["Keys"]) >= 2
            else f"Create a new {r['Type']} key"
        )
        if a1.button("🔄 Rotate", key=f"rot-{acct}-{user}", disabled=not can_rotate, help=why_not):
            rotate_dialog(acct, user)
        if a2.button("📧 Remind", key=f"rem-{acct}-{user}", disabled=rem["stopped"],
                     help="Reminders are stopped" if rem["stopped"] else "Draft a reminder in Gmail"):
            remind_dialog(acct, user)
        if rem["stopped"]:
            if a3.button("🔔 Resume", key=f"res-{acct}-{user}", help="Turn reminders back on"):
                reminders.set_stopped(acct, user, False)
                st.rerun()
        elif a3.button("🔕 Stop", key=f"stop-{acct}-{user}", help="Stop reminding this user"):
            reminders.set_stopped(acct, user, True)
            st.rerun()

# ================================================================ full table
with st.expander("All keys (table and CSV download)"):
    st.dataframe(keys_df, hide_index=True)
    st.download_button(
        "Download as CSV",
        keys_df.to_csv(index=False).encode("utf-8"),
        file_name=f"iam-keys-{now:%Y%m%d}.csv",
        mime="text/csv",
    )
