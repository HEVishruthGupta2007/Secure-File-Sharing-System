"""
Application factory. Builds and configures the Flask app: extensions,
blueprints, the upload folder, and the database tables.
"""

from flask import Flask, redirect, url_for
from flask_login import current_user

from .config import Config, BASE_DIR
from .extensions import db, login_manager


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)

    # Make sure the folders we need actually exist before anything writes to them.
    Config.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    (BASE_DIR / "instance").mkdir(parents=True, exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)

    from .models import User

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    from .auth.routes import auth_bp
    from .files.routes import files_bp
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(files_bp, url_prefix="/files")

    with app.app_context():
        db.create_all()

    @app.route("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("files.dashboard"))
        return redirect(url_for("auth.login_page"))

    return app
