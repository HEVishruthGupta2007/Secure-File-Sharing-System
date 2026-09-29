#!/usr/bin/env python3
"""
CODSOFT Cyber Security Internship - Task 5
==========================================
SECURE FILE SHARING SYSTEM

Entry point. Loads .env, builds the app, and runs the dev server.

FIRST-TIME SETUP
-----------------
  python -m venv venv
  .\\venv\\Scripts\\Activate.ps1       (Windows PowerShell)
  source venv/bin/activate             (macOS/Linux)
  pip install -r requirements.txt
  copy .env.example .env               (Windows)   |   cp .env.example .env   (macOS/Linux)
  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
  # paste that output into .env as MASTER_KEY=...
  python run.py
  # visit http://127.0.0.1:5001

The first account you register becomes an admin automatically.
"""

from dotenv import load_dotenv
load_dotenv()

from app import create_app  # noqa: E402  (must load .env first)

app = create_app()

if __name__ == "__main__":
    print("=" * 60)
    print(" Secure File Sharing System - CodSoft Task 5")
    print(" http://127.0.0.1:5001")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5001, debug=False)
