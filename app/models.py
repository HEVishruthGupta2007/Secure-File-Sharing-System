"""
Database models.

Roles, for RBAC:
  - "admin" can see and manage every file in the system.
  - "user" can only see files they own, plus files explicitly shared
    with them via a FileShare row.

The very first account created becomes an admin automatically (see
auth/routes.py) — a common bootstrap pattern so there's always at least
one admin without a separate setup script.
"""

import uuid
from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from .extensions import db


def utcnow() -> datetime:
    """Return timezone-naive UTC datetime for SQLite compatibility."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")  # "admin" | "user"
    created_at = db.Column(db.DateTime, default=utcnow)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def is_admin(self) -> bool:
        return self.role == "admin"


class FileRecord(db.Model):
    __tablename__ = "files"

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(64), unique=True, nullable=False)  # random name on disk
    wrapped_key = db.Column(db.LargeBinary, nullable=False)  # per-file key, encrypted by master key
    size_bytes = db.Column(db.Integer, nullable=False)
    content_type = db.Column(db.String(120), default="application/octet-stream")
    uploaded_at = db.Column(db.DateTime, default=utcnow)

    owner = db.relationship("User", backref="files")
    shares = db.relationship("FileShare", backref="file", cascade="all, delete-orphan")
    links = db.relationship("ShareLink", backref="file", cascade="all, delete-orphan")


class FileShare(db.Model):
    """RBAC grant: gives one specific user access to one specific file."""
    __tablename__ = "file_shares"

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey("files.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    permission = db.Column(db.String(20), nullable=False, default="download")  # "view" | "download"
    created_at = db.Column(db.DateTime, default=utcnow)

    user = db.relationship("User")

    __table_args__ = (db.UniqueConstraint("file_id", "user_id", name="uq_file_user_share"),)


class ShareLink(db.Model):
    """A temporary, tokenised download link — no login required to use it."""
    __tablename__ = "share_links"

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey("files.id"), nullable=False)
    token = db.Column(db.String(32), unique=True, nullable=False,
                       default=lambda: uuid.uuid4().hex)
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)

    created_by = db.relationship("User")

    def is_expired(self) -> bool:
        return utcnow() > self.expires_at
