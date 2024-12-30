import os
from flask import (
    Flask, render_template, redirect, url_for,
    request, jsonify, session, make_response
)
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager, login_user, current_user,
    logout_user, login_required, UserMixin
)
from datetime import datetime
from dotenv import load_dotenv
from urllib.parse import quote_plus

# Load environment variables from .env file
load_dotenv()


#########################
#   CONFIG CLASSES      #
#########################

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "default_secret_key")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # Force sessions to end on browser close
    SESSION_PERMANENT = False


class DevelopmentConfig(Config):
    DEBUG = True
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_USER = os.getenv("DB_USER", "root")
    DB_PASSWORD = quote_plus(os.getenv("DB_PASSWORD", ""))
    DB_NAME = os.getenv("DB_NAME", "ccc_emergency_map")
    SQLALCHEMY_DATABASE_URI = (
        f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}"
    )


class ProductionConfig(Config):
    DEBUG = False
    DB_HOST = os.getenv("DB_HOST")
    DB_USER = os.getenv("DB_USER")
    DB_PASSWORD = quote_plus(os.getenv("DB_PASSWORD", ""))
    DB_NAME = os.getenv("DB_NAME")
    SQLALCHEMY_DATABASE_URI = (
        f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}"
    )


#########################
#   APP & EXTENSIONS    #
#########################

# Determine Environment and Configure App
env = os.getenv("FLASK_ENV", "development")
if env == "production":
    app_config = ProductionConfig
else:
    app_config = DevelopmentConfig

app = Flask(__name__)
app.config.from_object(app_config)

# Database & Migrations
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Password hashing
bcrypt = Bcrypt(app)

# Flask-Login Setup
login_manager = LoginManager(app)
# If an unauthenticated user tries to access a protected route,
# it will redirect them to the 'login_page' route.
login_manager.login_view = "login_page"
login_manager.login_message_category = "info"


#########################
#     SESSION & CACHE   #
#########################

# Ensure each request does not make the session permanent
@app.before_request
def make_session_non_permanent():
    session.permanent = False


# Optional: Force no browser caching (prevents “back button” showing old page)
@app.after_request
def no_caching(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


#########################
#       MODELS          #
#########################

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


class Users(db.Model, UserMixin):
    __tablename__ = "users"
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    account_type = db.Column(db.String(20), nullable=False, default="customer")
    created_at = db.Column(db.DateTime, default=datetime.now())

    # One-to-many relationship: a user can have many ratings or emergencies
    ratings = db.relationship(
        "Ratings",
        backref="user",
        lazy=True,
        cascade="all, delete-orphan",
    )
    emergencies = db.relationship(
        "Emergencies",
        backref="user",
        lazy=True,
        cascade="all, delete-orphan",
    )

    # Required by Flask-Login to identify the user
    @property
    def id(self):
        return self.user_id


class Ratings(db.Model):
    __tablename__ = "ratings"
    rating_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.user_id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )
    rating_header = db.Column(db.String(100), nullable=False)
    rating_notes = db.Column(db.Text, nullable=False)
    rating_value = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now())


class Emergencies(db.Model):
    __tablename__ = "emergencies"
    emergency_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.user_id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )
    location_details = db.Column(db.Text, nullable=True)
    distress_notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now())


#########################
#       ROUTES          #
#########################

@app.route("/")
def index():
    # Always go to login page
    return redirect(url_for("login_page"))


@app.route("/login_page")
def login_page():
    """
    If the user is already authenticated,
    skip login page and go to the dashboard.
    Otherwise, load the login form.
    """
    if current_user.is_authenticated:
        return redirect(url_for("customer_dashboard"))
    return render_template("login.html")


@app.route("/signup_page")
def signup_page():
    """
    If the user is already authenticated,
    skip signup page and go to the dashboard.
    Otherwise, load the signup form.
    """
    if current_user.is_authenticated:
        return redirect(url_for("customer_dashboard"))
    return render_template("signup.html")


@app.route("/customer_dashboard")
@login_required
def customer_dashboard():
    """
    Dashboard only accessible to logged-in users.
    If for some reason an admin logs in, we could also check account_type:
    """
    if current_user.account_type != "customer":
        return redirect(url_for("index"))
    return render_template("customer_dashboard.html", username=current_user.username)


@app.route("/reviews_page")
@login_required
def reviews_page():
    if current_user.account_type != "customer":
        return redirect(url_for("index"))
    return render_template("customer_reviews.html")


@app.route("/submit_log_page")
@login_required
def submit_log_page():
    if current_user.account_type != "customer":
        return redirect(url_for("index"))
    return render_template("customer_submit_log.html")


##############################
#       API ENDPOINTS        #
##############################

@app.route("/api/signup", methods=["POST"])
def api_signup():
    """
    Creates a new user account.
    Expects JSON with keys: username, email, password, phone_number
    """
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    phone_number = data.get("phone_number")

    # Validate input
    if not username or not email or not password or not phone_number:
        return jsonify({"success": False, "message": "All fields are required."}), 400

    # Check if username or email already exist
    if Users.query.filter_by(username=username).first():
        return jsonify({"success": False, "message": "Username already exists!"}), 400
    if Users.query.filter_by(email=email).first():
        return jsonify({"success": False, "message": "Email already registered."}), 400

    # Hash password
    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
    new_user = Users(
        username=username,
        email=email,
        password_hash=hashed_password,
        phone_number=phone_number,
    )
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"success": True, "message": "Account created successfully!"}), 201
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Signup Error: {e}")
        return jsonify({"success": False, "message": "Database error."}), 500


@app.route("/api/login", methods=["POST"])
def api_login():
    """
    Logs the user in if credentials are valid.
    Expects JSON with keys: email, password
    """
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"success": False, "message": "Email and password are required."}), 400

    user = Users.query.filter_by(email=email).first()
    if user and bcrypt.check_password_hash(user.password_hash, password):
        # Critically, do NOT use remember=True to avoid persistent cookies
        login_user(user, remember=False)
        return jsonify({
            "success": True,
            "message": "Logged in successfully!",
            "account_type": user.account_type
        }), 200
    else:
        return jsonify({"success": False, "message": "Invalid email or password."}), 401


@app.route("/api/api_logou", methods=["POST"])
@login_required
def api_logout():
    """
    Logs the user out, clears the session, and
    removes the session cookie so they are not recognized again.
    Finally, redirects to login_page.
    """
    logout_user()        # Removes user_id from session
    session.clear()      # Clears all session data
    response = make_response(redirect(url_for("login_page")))
    # Explicitly remove the session cookie
    response.delete_cookie(app.config.get("SESSION_COOKIE_NAME", "session"))
    return response


@app.route("/api/reviews", methods=["GET", "POST"])
@login_required
def api_reviews():
    """
    GET: Fetches all reviews for the currently logged-in user.
    POST: Creates a new review for the logged-in user.
    """
    if current_user.account_type != "customer":
        return jsonify({"success": False, "message": "Unauthorized access."}), 403

    if request.method == "POST":
        data = request.get_json()
        rating_header = data.get("rating_header")
        rating_notes = data.get("rating_notes")
        rating_value = data.get("rating_value")

        if not rating_header or not rating_notes or rating_value is None:
            return jsonify({"success": False, "message": "All fields are required."}), 400

        # Validate rating_value is an integer 1 through 5
        try:
            rating_value = int(rating_value)
            if not (1 <= rating_value <= 5):
                raise ValueError
        except ValueError:
            return jsonify({"success": False, "message": "Rating must be between 1 and 5."}), 400

        new_review = Ratings(
            user_id=current_user.user_id,
            rating_header=rating_header,
            rating_notes=rating_notes,
            rating_value=rating_value,
        )
        try:
            db.session.add(new_review)
            db.session.commit()
            return jsonify({"success": True, "message": "Review submitted successfully!"}), 201
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Review Submission Error: {e}")
            return jsonify({"success": False, "message": "Database error."}), 500

    else:  # GET
        reviews = Ratings.query.filter_by(user_id=current_user.user_id).all()
        reviews_data = [
            {
                "rating_header": r.rating_header,
                "rating_notes": r.rating_notes,
                "rating_value": r.rating_value,
                "created_at": r.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            }
            for r in reviews
        ]
        return jsonify({"success": True, "reviews": reviews_data}), 200


@app.route("/api/emergency", methods=["GET", "POST"])
@login_required
def api_emergency():
    """
    GET: Fetches all emergencies for the currently logged-in user.
    POST: Creates a new emergency log for the logged-in user.
    """
    if current_user.account_type != "customer":
        return jsonify({"success": False, "message": "Unauthorized access."}), 403

    if request.method == "POST":
        data = request.get_json()
        location_details = data.get("location_details")
        distress_notes = data.get("distress_notes")

        if not location_details or not distress_notes:
            return jsonify({"success": False, "message": "All fields are required."}), 400

        new_emergency = Emergencies(
            user_id=current_user.user_id,
            location_details=location_details,
            distress_notes=distress_notes,
        )
        try:
            db.session.add(new_emergency)
            db.session.commit()
            return jsonify({"success": True, "message": "Emergency log submitted successfully!"}), 201
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Emergency Log Submission Error: {e}")
            return jsonify({"success": False, "message": "Database error."}), 500

    else:  # GET
        emergencies = Emergencies.query.filter_by(user_id=current_user.user_id).all()
        emergencies_data = [
            {
                "location_details": e.location_details,
                "distress_notes": e.distress_notes,
                "created_at": e.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            }
            for e in emergencies
        ]
        return jsonify({"success": True, "emergencies": emergencies_data}), 200


#########################
#    RUN THE APP        #
#########################

if __name__ == "__main__":
    # In dev, typically use app.run(debug=True)
    app.run(debug=True)