import os
import smtplib
import socket
import random
import ssl
import string
from datetime import datetime, timedelta
from email.message import EmailMessage

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
from flask_mail import Mail, Message

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
    SESSION_PERMANENT = False

class DevelopmentConfig(Config):
    DEBUG = True
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_USER = os.getenv("DB_USER", "root")
    DB_PASSWORD = quote_plus(os.getenv("DB_PASSWORD", "Preston-2020"))
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

env = os.getenv("FLASK_ENV", "development")
if env == "production":
    app_config = ProductionConfig
else:
    app_config = DevelopmentConfig

app = Flask(__name__)
app.config.from_object(app_config)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
login_manager.login_view = "login_page"
login_manager.login_message_category = "info"

app.config['MAIL_SERVER'] = 'smtp.example.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
mail = Mail(app)

#########################
#     SESSION & CACHE   #
#########################

@app.before_request
def make_session_non_permanent():
    session.permanent = False

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
    chat_messages = db.relationship(
        "ChatMessages",
        back_populates="user",
        lazy=True,
        cascade="all, delete-orphan",
    )
    mfa_entries = db.relationship(
        "MFA",
        backref="user",
        lazy=True,
        cascade="all, delete-orphan",
    )

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

class ChatMessages(db.Model):
    __tablename__ = "chat_messages"
    message_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.user_id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False,
    )
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("Users", back_populates="chat_messages")

class MFA(db.Model):
    __tablename__ = "mfa"
    mfa_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    code = db.Column(db.String(6), nullable=False)
    expiration = db.Column(db.DateTime, nullable=False)

#########################
#       ROUTES          #
#########################

@app.route("/request_otp_page", methods=["GET", "POST"])
@login_required
def request_otp_page():
    if request.method == "POST":
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({"success": False, "message": "Email and password are required."}), 400

        if email != current_user.email or not bcrypt.check_password_hash(current_user.password_hash, password):
            return jsonify({"success": False, "message": "Invalid email or password."}), 401

        verification_code = generate_otp()
        expiration = datetime.utcnow() + timedelta(minutes=10)
        mfa_entry = MFA.query.filter_by(user_id=current_user.user_id).first()
        if mfa_entry:
            mfa_entry.code = verification_code
            mfa_entry.expiration = expiration
        else:
            mfa_entry = MFA(user_id=current_user.user_id, code=verification_code, expiration=expiration)
            db.session.add(mfa_entry)

        try:
            db.session.commit()
            send_verification_email(current_user.email, current_user.username, verification_code)
            return jsonify({"success": True, "message": "Verification code sent to your email."}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "message": f"Failed to send verification code: {str(e)}"}), 500

    return render_template("request_otp_page.html")

@app.route("/otp_verify", methods=["GET", "POST"])
@login_required
def otp_verify():
    if request.method == "POST":
        data = request.get_json()
        verification_code = data.get("otp")

        if not verification_code:
            return jsonify({"success": False, "message": "Verification code is required."}), 400

        mfa_entry = MFA.query.filter_by(user_id=current_user.user_id, code=verification_code).first()
        if not mfa_entry or mfa_entry.expiration < datetime.utcnow():
            return jsonify({"success": False, "message": "Invalid or expired verification code."}), 400

        session["otp_verified"] = True
        return jsonify({"success": True, "message": "Verification code verified successfully."}), 200

    return render_template("otp_verify.html")

@app.route("/update_account", methods=["GET", "POST"])
@login_required
def update_account():
    if not session.get("otp_verified"):
        return redirect(url_for("request_otp_page"))

    if request.method == "POST":
        data = request.get_json()
        new_email = data.get("new_email")
        new_password = data.get("new_password")
        new_phone = data.get("new_phone")

        if new_email:
            current_user.email = new_email
        if new_password:
            current_user.password_hash = bcrypt.generate_password_hash(new_password).decode("utf-8")
        if new_phone:
            current_user.phone_number = new_phone

        try:
            db.session.commit()
            session.pop("otp_verified", None)
            return jsonify({"success": True, "message": "Account updated successfully!"}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "message": "Database error."}), 500

    return render_template("account_update.html")




@app.route("/")
def index():
    return redirect(url_for("login_page"))

@app.route("/login_page")
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for("customer_dashboard"))
    return render_template("login.html")

@app.route("/signup_page")
def signup_page():
    if current_user.is_authenticated:
        return redirect(url_for("customer_dashboard"))
    return render_template("signup.html")

@app.route("/customer_dashboard")
@login_required
def customer_dashboard():
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

@app.route("/chat")
@login_required
def chat():
    if current_user.account_type != "customer":
        return redirect(url_for("index"))
    return render_template("chat.html", username=current_user.username)

@app.route("/account_update")
@login_required
def account_update():
    """
    Page for updating account information (email and password).
    Accessible only after MFA verification.
    """
    if not session.get("otp_verified"):
        return redirect(url_for("request_otp_page"))
    return render_template("account_update.html")



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
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"success": False, "message": "Email and password are required."}), 400

    user = Users.query.filter_by(email=email).first()
    if user and bcrypt.check_password_hash(user.password_hash, password):
        login_user(user, remember=False)
        return jsonify({
            "success": True,
            "message": "Logged in successfully!",
            "account_type": user.account_type
        }), 200
    else:
        return jsonify({"success": False, "message": "Invalid email or password."}), 401

@app.route("/api/logout", methods=["POST"])
@login_required
def api_logout():
    """
    Logs out the user and redirects to the login page.
    """
    logout_user()        # Removes user_id from session
    session.clear()      # Clears all session data
    return redirect(url_for("login_page"))  # Redirect to login page


@app.route("/api/reviews", methods=["GET", "POST"])
@login_required
def api_reviews():
    if current_user.account_type != "customer":
        return jsonify({"success": False, "message": "Unauthorized access."}), 403

    if request.method == "POST":
        data = request.get_json()
        rating_header = data.get("rating_header")
        rating_notes = data.get("rating_notes")
        rating_value = data.get("rating_value")

        if not rating_header or not rating_notes or rating_value is None:
            return jsonify({"success": False, "message": "All fields are required."}), 400

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

    else:
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

    else:
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

@app.route("/api/chat/messages", methods=["GET", "POST"])
@login_required
def api_chat_messages():
    if request.method == "POST":
        data = request.get_json()
        message = data.get("message", "").strip()

        if not message:
            return jsonify({"success": False, "message": "Message cannot be empty."}), 400

        new_message = ChatMessages(user_id=current_user.user_id, message=message)
        try:
            db.session.add(new_message)
            db.session.commit()
            return jsonify({"success": True, "message": "Message sent successfully!"}), 201
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error saving message: {e}")
            return jsonify({"success": False, "message": "Database error."}), 500

    elif request.method == "GET":
        messages = ChatMessages.query.order_by(ChatMessages.timestamp.asc()).all()
        message_list = [
            {
                "username": msg.user.username,
                "message": msg.message,
                "timestamp": msg.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            }
            for msg in messages
        ]
        return jsonify({"success": True, "messages": message_list}), 200

#########################
#    RUN THE APP        #
#########################

def send_verification_email(to_email, username, verification_code):
    email_sender = os.getenv("MAIL_USERNAME")
    email_password = os.getenv("MAIL_PASSWORD")

    subject = "Cave Country Canoes Account Verification Code"
    body = f"""
    Dear {username},

    Your verification code is {verification_code}.

    - Cave Country Canoes
    """

    em = EmailMessage()
    em["From"] = email_sender
    em["To"] = to_email
    em["Subject"] = subject
    em.set_content(body)

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as smtp:
        smtp.login(email_sender, email_password)
        smtp.sendmail(email_sender, to_email, em.as_string())


def generate_otp():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

def get_local_ip():
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        return local_ip
    except Exception as e:
        print(f"Error retrieving local IP: {e}")
        return "127.0.0.1"

if __name__ == "__main__":
    local_ip = get_local_ip()
    print(f"Flask app running on: http://{local_ip}:5000")
    app.run(host=local_ip, port=5000, debug=True)