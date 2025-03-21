import os
from flask import Flask
from .extensions import db, migrate, bcrypt, login_manager, mail, csrf



def create_app():
    # Determine the absolute path for the templates folder.
    template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "templates"))
    # Determine the absolute path for the static folder (located inside the 'app' folder)
    static_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "static"))

    # Create the Flask app and explicitly set the static folder.
    app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)

    # Load configuration based on FLASK_ENV environment variable.
    if os.environ.get("FLASK_ENV") == "production":
        app.config.from_object("config.ProductionConfig")
    else:
        app.config.from_object("config.DevelopmentConfig")

    # Optionally override the static folder and URL path from config (if set)
    app.static_folder = app.config.get("STATIC_FOLDER", static_dir)
    app.static_url_path = app.config.get("STATIC_URL_PATH", "/static")

    # Initialize extensions.
    db.init_app(app)
    migrate.init_app(app, db)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    csrf.init_app(app)

    # Create database tables if they don't exist.
    with app.app_context():
        db.create_all()

    # Import models so the user loader can be registered.
    from .models import Users

    @login_manager.user_loader
    def load_user(user_id):
        """Load and return the user object for the given user ID."""
        return Users.query.get(int(user_id))

    # Register the main blueprint (all routes are defined in routes.py).
    from .routes import bp as main_bp
    app.register_blueprint(main_bp)

    # Global context processor to inject variables into templates.
    @app.context_processor
    def inject_globals():
        from flask_login import current_user
        from datetime import datetime
        return {
            "session_token": current_user.session_token if current_user.is_authenticated else "",
            "datetime": datetime,
            "debug": app.config.get("DEBUG", False)
        }

    return app
