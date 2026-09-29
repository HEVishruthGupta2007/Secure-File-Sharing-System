"""
Authentication: registration, login, logout.

Sessions are handled by Flask-Login, which sets a signed cookie after
login_user() — the cookie proves identity on every later request without
sending the password again. Passwords are never stored directly, only a
salted hash (werkzeug.security.generate_password_hash, PBKDF2 by default).
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user

from ..extensions import db
from ..models import User

auth_bp = Blueprint("auth", __name__, template_folder="../templates")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("files.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not username or not email or not password:
            flash("All fields are required.", "error")
            return redirect(url_for("auth.register"))
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return redirect(url_for("auth.register"))
        if len(username) > 64 or len(email) > 120:
            flash("Username or email is too long.", "error")
            return redirect(url_for("auth.register"))
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("That username or email is already taken.", "error")
            return redirect(url_for("auth.register"))

        # The very first account bootstraps as admin; everyone after is "user".
        role = "admin" if User.query.count() == 0 else "user"

        user = User(username=username, email=email, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        login_user(user)
        flash("Account created." + (" You are the first user, so you're an admin." if role == "admin" else ""), "success")
        return redirect(url_for("files.dashboard"))

    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for("files.dashboard"))

    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")

        if not identifier or not password:
            flash("Username/email and password are required.", "error")
            return redirect(url_for("auth.login_page"))

        user = User.query.filter(
            (User.username == identifier) | (User.email == identifier.lower())
        ).first()

        if user is None or not user.check_password(password):
            flash("Incorrect username/email or password.", "error")
            return redirect(url_for("auth.login_page"))

        login_user(user)
        return redirect(url_for("files.dashboard"))

    return render_template("login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.", "success")
    return redirect(url_for("auth.login_page"))
