"""
Everything to do with files: upload, download, sharing (RBAC), and
temporary expiring links.

Every route that touches a specific file calls can_access() first — that
single function is the one place access control decisions get made, which
matters for a security-relevant app: one function to audit, not scattered
checks copy-pasted across routes.
"""

import io
import uuid
from datetime import timedelta
from pathlib import Path

from flask import (
    Blueprint, render_template, request, redirect, url_for,
    flash, send_file, abort, current_app,
)
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename

from ..extensions import db
from ..models import User, FileRecord, FileShare, ShareLink, utcnow
from ..crypto_utils import generate_file_key, encrypt_bytes, decrypt_bytes, wrap_key, unwrap_key

files_bp = Blueprint("files", __name__, template_folder="../templates")


def can_access(user, record: FileRecord, need: str = "view") -> bool:
    """
    The single centralized access-control decision point (RBAC).

    - Admins and the file's owner can always do anything with it.
    - Anyone else needs an explicit FileShare grant:
      - "manage" permission is only for admin and owner (returns False for share recipients).
      - "view" grant covers seeing the file listed.
      - "download" grant is required to actually download the bytes.
    """
    if user.is_admin() or record.owner_id == user.id:
        return True
    if need == "manage":
        return False
    share = FileShare.query.filter_by(file_id=record.id, user_id=user.id).first()
    if share is None:
        return False
    if need == "download":
        return share.permission == "download"
    return True


@files_bp.route("/")
@login_required
def dashboard():
    if current_user.is_admin():
        owned = FileRecord.query.order_by(FileRecord.uploaded_at.desc()).all()
    else:
        owned = (FileRecord.query.filter_by(owner_id=current_user.id)
                 .order_by(FileRecord.uploaded_at.desc()).all())

    shared_with_me = (
        FileRecord.query.join(FileShare, FileShare.file_id == FileRecord.id)
        .filter(FileShare.user_id == current_user.id)
        .order_by(FileRecord.uploaded_at.desc())
        .all()
    )
    other_users = User.query.filter(User.id != current_user.id).order_by(User.username).all()

    return render_template(
        "dashboard.html",
        owned=owned,
        shared_with_me=shared_with_me,
        other_users=other_users,
    )


@files_bp.route("/upload", methods=["POST"])
@login_required
def upload():
    f = request.files.get("file")
    if not f or f.filename == "":
        flash("Choose a file first.", "error")
        return redirect(url_for("files.dashboard"))

    raw = f.read()

    # Envelope encryption: a fresh key for this one file, then that key
    # gets wrapped (encrypted) with the master key before it's stored.
    file_key = generate_file_key()
    encrypted = encrypt_bytes(raw, file_key)
    wrapped = wrap_key(file_key)

    stored_name = uuid.uuid4().hex
    dest = Path(current_app.config["UPLOAD_DIR"]) / stored_name
    dest.write_bytes(encrypted)

    record = FileRecord(
        owner_id=current_user.id,
        original_filename=secure_filename(f.filename) or "file",
        stored_filename=stored_name,
        wrapped_key=wrapped,
        size_bytes=len(raw),
        content_type=f.mimetype or "application/octet-stream",
    )
    db.session.add(record)
    db.session.commit()

    flash(f'"{record.original_filename}" uploaded and encrypted.', "success")
    return redirect(url_for("files.dashboard"))


def _stream_decrypted(record: FileRecord):
    path = Path(current_app.config["UPLOAD_DIR"]) / record.stored_filename
    if not path.is_file():
        abort(404)
    encrypted = path.read_bytes()
    file_key = unwrap_key(record.wrapped_key)
    plaintext = decrypt_bytes(encrypted, file_key)

    return send_file(
        io.BytesIO(plaintext),
        mimetype=record.content_type,
        as_attachment=True,
        download_name=record.original_filename,
    )


@files_bp.route("/<int:file_id>/download")
@login_required
def download(file_id):
    record = FileRecord.query.get_or_404(file_id)
    if not can_access(current_user, record, need="download"):
        abort(403)
    return _stream_decrypted(record)


@files_bp.route("/<int:file_id>/delete", methods=["POST"])
@login_required
def delete(file_id):
    record = FileRecord.query.get_or_404(file_id)
    if not can_access(current_user, record, need="manage"):
        abort(403)

    path = Path(current_app.config["UPLOAD_DIR"]) / record.stored_filename
    path.unlink(missing_ok=True)
    db.session.delete(record)
    db.session.commit()

    flash("File deleted.", "success")
    return redirect(url_for("files.dashboard"))


@files_bp.route("/<int:file_id>/share", methods=["POST"])
@login_required
def share(file_id):
    record = FileRecord.query.get_or_404(file_id)
    if not can_access(current_user, record, need="manage"):
        abort(403)

    username = request.form.get("username", "").strip()
    permission = request.form.get("permission", "download")
    if permission not in ("view", "download"):
        permission = "download"

    target = User.query.filter_by(username=username).first()
    if target is None:
        flash(f'No user named "{username}".', "error")
        return redirect(url_for("files.dashboard"))
    if target.id == record.owner_id:
        flash("That user already owns the file.", "error")
        return redirect(url_for("files.dashboard"))

    existing = FileShare.query.filter_by(file_id=record.id, user_id=target.id).first()
    if existing:
        existing.permission = permission
    else:
        db.session.add(FileShare(file_id=record.id, user_id=target.id, permission=permission))
    db.session.commit()

    flash(f'Shared "{record.original_filename}" with {target.username} ({permission}).', "success")
    return redirect(url_for("files.dashboard"))


@files_bp.route("/<int:file_id>/unshare/<int:user_id>", methods=["POST"])
@login_required
def unshare(file_id, user_id):
    record = FileRecord.query.get_or_404(file_id)
    if not can_access(current_user, record, need="manage"):
        abort(403)

    share = FileShare.query.filter_by(file_id=file_id, user_id=user_id).first()
    if share:
        db.session.delete(share)
        db.session.commit()
    flash("Access revoked.", "success")
    return redirect(url_for("files.dashboard"))


@files_bp.route("/<int:file_id>/link", methods=["POST"])
@login_required
def create_link(file_id):
    record = FileRecord.query.get_or_404(file_id)
    if not can_access(current_user, record, need="manage"):
        abort(403)

    minutes = request.form.get("minutes", type=int) or 60
    minutes = max(1, min(minutes, 60 * 24 * 7))  # clamp: 1 minute .. 7 days

    link = ShareLink(
        file_id=record.id,
        created_by_id=current_user.id,
        expires_at=utcnow() + timedelta(minutes=minutes),
    )
    db.session.add(link)
    db.session.commit()

    link_url = url_for("files.download_via_link", token=link.token, _external=True)
    flash(f"Temporary link (expires in {minutes} min): {link_url}", "success")
    return redirect(url_for("files.dashboard"))


@files_bp.route("/link/<token>")
def download_via_link(token):
    """No @login_required here on purpose — the whole point of this route
    is that the token itself is the credential, valid until it expires."""
    link = ShareLink.query.filter_by(token=token).first()
    if link is None:
        abort(404)
    if link.is_expired():
        abort(410)  # 410 Gone: existed once, deliberately no longer available
    if not link.file:
        abort(404)
    return _stream_decrypted(link.file)
