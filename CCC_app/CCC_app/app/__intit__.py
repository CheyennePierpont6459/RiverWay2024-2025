from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)

    # Set configurations (Update these values depending environment)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:Preston-2020@localhost/ccc_emergency_map'
    app.config['SECRET_KEY'] = 'your_secret_key'

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'app.login'  # Redirect to login if not logged in

    # Import routes and register blueprint
    from .routes import app as routes_blueprint
    app.register_blueprint(routes_blueprint)

    return app
