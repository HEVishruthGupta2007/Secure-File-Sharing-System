"""
Shared extension instances. Created here (not inside create_app) so that
models.py and route modules can import `db` without circular imports.
"""

from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

db = SQLAlchemy()

login_manager = LoginManager()
login_manager.login_view = "auth.login_page"
login_manager.login_message = "Please log in to continue."
login_manager.login_message_category = "error"
