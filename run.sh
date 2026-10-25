#!/usr/bin/env bash
# Mac/Linux launcher. Creates a virtual environment on first run.
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -d .venv ]; then
  python3 -m venv .venv
  .venv/bin/pip install --upgrade pip
  .venv/bin/pip install -r requirements.txt
fi
[ -f accounts.json ] || { cp accounts.example.json accounts.json; echo "Created accounts.json. Edit it with your account IDs."; }
exec .venv/bin/streamlit run app.py
