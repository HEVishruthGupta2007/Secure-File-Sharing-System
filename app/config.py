"""
Configuration for the Secure File Sharing System.

The MASTER_KEY is the root of the whole encryption scheme: every uploaded
file gets its own random key (generated at upload time), and that per-file
key is itself encrypted ("wrapped") using this master key before being
stored in the database. This is called envelope encryption — the master
key never touches file contents directly, and losing one file's key can
never expose another file.

Generate a master key with:
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
and put the output in your .env file (see .env.example).
"""

import os
from pathlib import Path
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# Ensure .env is loaded even if config is imported directly before create_app
load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")

    _db_url = os.environ.get("DATABASE_URL")
    if _db_url:
        # Handle relative sqlite URLs like sqlite:///instance/app.db or sqlite:///app.db
        # Flask-SQLAlchemy resolves relative SQLite paths against app.instance_path (<BASE_DIR>/instance)
        if _db_url.startswith("sqlite:///instance/"):
            rel_file = _db_url[len("sqlite:///instance/"):]
            _db_url = f"sqlite:///{(BASE_DIR / 'instance' / rel_file).as_posix()}"
        elif _db_url == "sqlite:///app.db":
            _db_url = f"sqlite:///{(BASE_DIR / 'instance' / 'app.db').as_posix()}"
        SQLALCHEMY_DATABASE_URI = _db_url
    else:
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{(BASE_DIR / 'instance' / 'app.db').as_posix()}"

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    UPLOAD_DIR = BASE_DIR / "uploads"
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100 MB per upload

    _master_key = os.environ.get("MASTER_KEY")
    if not _master_key or not _master_key.strip():
        raise RuntimeError(
            "MASTER_KEY is not set.\n"
            "Generate one with:\n"
            '  python -c "from cryptography.fernet import Fernet; '
            'print(Fernet.generate_key().decode())"\n'
            "then copy .env.example to .env and paste it in."
        )

    _master_key_bytes = _master_key.strip().encode()
    try:
        Fernet(_master_key_bytes)
    except Exception as e:
        raise RuntimeError(
            f"MASTER_KEY is invalid ({e}).\n"
            "Generate one with:\n"
            '  python -c "from cryptography.fernet import Fernet; '
            'print(Fernet.generate_key().decode())"\n'
            "then copy .env.example to .env and paste it in."
        )
    MASTER_KEY = _master_key_bytes
