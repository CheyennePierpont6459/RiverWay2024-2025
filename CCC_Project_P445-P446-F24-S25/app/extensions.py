"""
Module for application extensions.

Initializes extensions used by the application (SQLAlchemy, Migrate, Bcrypt,
LoginManager, Mail, CSRFProtect). Import these in other modules as needed.
"""

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_mail import Mail
from flask_wtf import CSRFProtect

db = SQLAlchemy()
migrate = Migrate()
bcrypt = Bcrypt()
login_manager = LoginManager()
mail = Mail()
csrf = CSRFProtect()

