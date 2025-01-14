﻿import hashlib
import os
import secrets
import smtplib
import socket
import ssl
from datetime import datetime, timedelta
from email.message import EmailMessage
import traceback  # For detailed error logging

from flask import (
    Flask, render_template, redirect, url_for,
    request, jsonify, session, flash, abort
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
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError, SAWarning
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect

import warnings

warnings.filterwarnings("ignore", category=SAWarning)  # Temporarily suppress SAWarnings

# Load environment variables from .env file
load_dotenv()


#########################
#      CONFIGURATION    #
#########################

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "defaultsecretkey")
    SQLALCHEMY_DATABASE_URI = (
        f"mysql+pymysql://{os.getenv('DB_USER')}:{quote_plus(os.getenv('DB_PASSWORD', ''))}@{os.getenv('DB_HOST')}/{os.getenv('DB_NAME')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class DevelopmentConfig(Config):
    DEBUG = True


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

# Mail config
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 465))
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = app.config['MAIL_USERNAME']

mail = Mail(app)

# CSRF Protection
csrf = CSRFProtect(app)

# Limiter Initialization (Memory store for dev/testing)
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)
limiter.init_app(app)


#########################
#  HELPER FUNCTIONS     #
#########################

def parse_assigned_employee_id(distress_text):
    if not distress_text:
        return None
    start = distress_text.find("[ASSIGNED_EMPLOYEE=")
    if start == -1:
        return None
    end = distress_text.find("]", start)
    if end == -1:
        return None
    marker = distress_text[start:end + 1]
    try:
        eq_pos = marker.index("=")
        num_str = marker[eq_pos + 1:-1]
        return int(num_str)
    except:
        return None


def update_assigned_employee_id(distress_text, new_employee_id=None):
    if not distress_text:
        distress_text = ""
    start = distress_text.find("[ASSIGNED_EMPLOYEE=")
    if start != -1:
        end = distress_text.find("]", start)
        if end != -1:
            distress_text = distress_text[:start] + distress_text[end + 1:]
    distress_text = distress_text.strip()

    if new_employee_id is not None:
        marker = f"[ASSIGNED_EMPLOYEE={new_employee_id}]"
        if distress_text:
            distress_text += "\n" + marker
        else:
            distress_text = marker
    return distress_text.strip()


def generate_secure_otp():
    random_bytes = secrets.token_bytes(16)
    return hashlib.sha256(random_bytes).hexdigest()[:6].upper()


def get_local_ip():
    try:
        hostname = socket.gethostname()
        return socket.gethostbyname(hostname)
    except:
        return "127.0.0.1"


#########################
#       MODELS          #
#########################

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(Users, int(user_id))


class Users(db.Model, UserMixin):
    __tablename__ = "users"
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    account_type = db.Column(db.String(20), nullable=False, default="customer")
    is_locked = db.Column(db.Boolean, nullable=False, default=False)
    session_token = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now())

    # Provide the property for Flask-Login to see "id"
    @property
    def id(self):
        return self.user_id

    # Relationship for assigned emergencies (employee side)
    assigned_emergencies = db.relationship(
        "Emergencies",
        back_populates="assigned_employee",
        lazy=True,
        foreign_keys="Emergencies.assigned_employee_id"
    )

    # Relationship for emergencies created by user (customer side)
    emergencies_created = db.relationship(
        "Emergencies",
        back_populates="customer",
        lazy=True,
        foreign_keys="Emergencies.user_id"
    )


class Ratings(db.Model):
    __tablename__ = "ratings"
    rating_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.user_id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False
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
        nullable=False
    )
    location_details = db.Column(db.Text, nullable=True)
    distress_notes = db.Column(db.Text, nullable=True)
    assigned_employee_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now())

    assigned_employee = db.relationship(
        "Users",
        back_populates="assigned_emergencies",
        foreign_keys=[assigned_employee_id]
    )

    customer = db.relationship(
        "Users",
        back_populates="emergencies_created",
        foreign_keys=[user_id]
    )


class ChatMessages(db.Model):
    __tablename__ = "chat_messages"
    message_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.user_id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False
    )
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class MFA(db.Model):
    __tablename__ = "mfa"
    mfa_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    code = db.Column(db.String(6), nullable=False)
    expiration = db.Column(db.DateTime, nullable=False)


##############################
#       ROUTES / VIEWS       #
##############################

@app.route("/")
def index():
    return redirect(url_for("login_page"))


@app.route("/login_page")
def login_page():
    if current_user.is_authenticated:
        if current_user.account_type in ["admin", "super_admin"]:
            return redirect(url_for("admin_home"))
        elif current_user.account_type == "customer":
            return redirect(url_for("customer_dashboard"))
        elif current_user.account_type == "employee":
            return redirect(url_for("employee_dashboard"))
    return render_template("login.html")


@app.route("/signup_page")
def signup_page():
    if current_user.is_authenticated:
        if current_user.account_type in ["admin", "super_admin"]:
            return redirect(url_for("admin_home"))
        elif current_user.account_type == "customer":
            return redirect(url_for("customer_dashboard"))
        elif current_user.account_type == "employee":
            return redirect(url_for("employee_dashboard"))
    return render_template("signup.html")


@app.route("/customer_dashboard")
@login_required
def customer_dashboard():
    if current_user.account_type == "customer":
        return render_template("customer_dashboard.html", username=current_user.username)
    elif current_user.account_type in ["admin", "super_admin"]:
        return redirect(url_for("admin_home"))
    else:
        return redirect(url_for("employee_dashboard"))


@app.route("/employee_dashboard")
@login_required
def employee_dashboard():
    if current_user.account_type not in ["employee", "admin", "super_admin"]:
        return redirect(url_for("login_page"))
    if current_user.account_type != "employee":
        if current_user.account_type in ["admin", "super_admin"]:
            return redirect(url_for("admin_home"))
        else:
            return redirect(url_for("customer_dashboard"))
    assigned_emergencies = Emergencies.query.filter_by(
        assigned_employee_id=current_user.user_id
    ).all()
    return render_template(
        "employee_dashboard.html",
        username=current_user.username,
        emergencies=assigned_emergencies
    )


@app.route("/reviews_page")
@login_required
def reviews_page():
    if current_user.account_type != "customer":
        if current_user.account_type in ["admin", "super_admin"]:
            return redirect(url_for("admin_home"))
        else:
            return redirect(url_for("employee_dashboard"))
    return render_template("customer_reviews.html")


@app.route("/submit_log_page")
@login_required
def submit_log_page():
    if current_user.account_type != "customer":
        if current_user.account_type in ["admin", "super_admin"]:
            return redirect(url_for("admin_home"))
        else:
            return redirect(url_for("employee_dashboard"))
    return render_template("customer_submit_log.html")


@app.route("/chat")
@login_required
def chat():
    return render_template("chat.html", username=current_user.username, account_type=current_user.account_type)


##############################
#   ADMIN DASHBOARD ROUTES   #
##############################

@app.route("/admin/home")
@login_required
def admin_home():
    if current_user.account_type not in ["admin", "super_admin"]:
        if current_user.account_type == "employee":
            return redirect(url_for("employee_dashboard"))
        return redirect(url_for("customer_dashboard"))

    total_customers = Users.query.filter_by(account_type="customer").count()
    total_employees = Users.query.filter_by(account_type="employee").count()
    total_emergencies = Emergencies.query.count()
    unresolved_emergencies = Emergencies.query.filter(
        Emergencies.assigned_employee_id == None
    ).count()

    stats = {
        "total_customers": total_customers,
        "total_employees": total_employees,
        "total_emergencies": total_emergencies,
        "unresolved_emergencies": unresolved_emergencies
    }
    return render_template("admin_home.html", stats=stats)


@app.route("/admin/manage_staff")
@login_required
def admin_manage_staff():
    if current_user.account_type not in ["admin", "super_admin"]:
        if current_user.account_type == "employee":
            return redirect(url_for("employee_dashboard"))
        return redirect(url_for("customer_dashboard"))

    employees = Users.query.filter_by(account_type="employee").all()
    if current_user.account_type == "super_admin":
        admins = Users.query.filter_by(account_type="admin").all()
    else:
        admins = []
    return render_template("admin_manage_staff.html", employees=employees, admins=admins)


@app.route("/admin/manage_emergencies")
@login_required
def admin_manage_emergencies():
    if current_user.account_type not in ["admin", "super_admin"]:
        if current_user.account_type == "employee":
            return redirect(url_for("employee_dashboard"))
        return redirect(url_for("customer_dashboard"))

    all_ems = Emergencies.query.all()
    employees = Users.query.filter_by(account_type="employee").all()

    data_emergencies = []
    for em in all_ems:
        assigned_user = db.session.get(Users, em.assigned_employee_id) if em.assigned_employee_id else None
        customer_obj = db.session.get(Users, em.user_id)
        customer_name = customer_obj.username if customer_obj else "Unknown"
        customer_phone = customer_obj.phone_number if customer_obj else "N/A"

        data_emergencies.append({
            "emergency_id": em.emergency_id,
            "location_details": em.location_details,
            "distress_notes": em.distress_notes,
            "assigned_employee_id": em.assigned_employee_id,
            "assigned_employee_name": assigned_user.username if assigned_user else None,
            "customer_name": customer_name,
            "customer_phone": customer_phone
        })

    return render_template(
        "admin_manage_emergencies.html",
        emergencies=data_emergencies,
        employees=employees
    )


@app.route("/admin/chat")
@login_required
def admin_chat():
    if current_user.account_type not in ["admin", "super_admin"]:
        if current_user.account_type == "employee":
            return redirect(url_for("employee_dashboard"))
        return redirect(url_for("customer_dashboard"))
    return render_template("admin_chat.html", username=current_user.username, account_type=current_user.account_type)


##############################
#  SIGNUP, LOGIN, LOGOUT     #
##############################

@app.route("/api/signup", methods=["POST"])
@csrf.exempt
def api_signup():
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    phone_number = data.get("phone_number")

    if not username or not email or not password or not phone_number:
        return jsonify({"success": False, "message": "All fields are required."}), 400

    if Users.query.filter_by(username=username).first():
        return jsonify({"success": False, "message": "Username already exists!"}), 400
    if Users.query.filter_by(email=email).first():
        return jsonify({"success": False, "message": "Email already registered."}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
    new_user = Users(
        username=username,
        email=email,
        password_hash=hashed_password,
        phone_number=phone_number,
        account_type="customer"
    )
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"success": True, "message": "Account created successfully!"}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": f"Database error: {e}"}), 500


@app.route("/api/login", methods=["POST"])
@csrf.exempt
def api_login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        app.logger.warning("Login attempt with missing email or password.")
        return jsonify({"success": False, "message": "Email and password are required."}), 400

    user = Users.query.filter_by(email=email).first()
    if user:
        if user.is_locked:
            app.logger.warning(f"Locked user {user.username} attempted to log in.")
            return jsonify({"success": False, "message": "Your account is locked. Please contact support."}), 403

        if bcrypt.check_password_hash(user.password_hash, password):
            user.session_token = secrets.token_hex(32)
            db.session.commit()
            login_user(user, remember=False)
            session['session_token'] = user.session_token
            app.logger.info(f"User {user.username} logged in successfully.")
            return jsonify({
                "success": True,
                "message": "Logged in successfully!",
                "account_type": user.account_type
            }), 200
        else:
            app.logger.warning(f"Failed login attempt for user {user.username}. Incorrect password.")
            return jsonify({"success": False, "message": "Invalid email or password."}), 401
    else:
        app.logger.warning(f"Failed login attempt for non-existent email: {email}.")
        return jsonify({"success": False, "message": "Invalid email or password."}), 401


@app.route("/api/logout", methods=["GET", "POST"])
@csrf.exempt
@login_required
def logout():
    if current_user.account_type == "super_admin":
        try:
            current_user.account_type = "admin"
            db.session.commit()
            app.logger.info(f"User {current_user.username} reverted to admin upon logout at {datetime.now()}")
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error reverting super_admin to admin: {e}")
            return jsonify({"success": False, "message": "Logout failed due to server error."}), 500

    current_user.session_token = None
    db.session.commit()
    logout_user()
    session.clear()
    return redirect(url_for("login_page"))


##############################
#   FORGOT PASSWORD          #
##############################

@app.route("/forgot_password", methods=["GET", "POST"])
@csrf.exempt
def forgot_password():
    if request.method == "POST":
        data = request.get_json()
        email = data.get("email")
        if not email:
            return jsonify({"success": False, "message": "Email is required."}), 400

        user = Users.query.filter_by(email=email).first()
        if not user or user.account_type != "customer":
            return jsonify({"success": False, "message": "Invalid or not a customer."}), 400

        verification_code = generate_secure_otp()
        expiration = datetime.now() + timedelta(minutes=10)
        mfa_entry = MFA.query.filter_by(user_id=user.user_id).first()
        if mfa_entry:
            mfa_entry.code = verification_code
            mfa_entry.expiration = expiration
        else:
            mfa_entry = MFA(user_id=user.user_id, code=verification_code, expiration=expiration)
            db.session.add(mfa_entry)

        try:
            db.session.commit()
            send_verification_email(user.email, user.username, verification_code)
            return jsonify({"success": True, "message": "OTP sent to your email."}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "message": f"DB error: {e}"}), 500

    return render_template("forgot_password.html")


@app.route("/reset_password", methods=["GET", "POST"])
@csrf.exempt
@login_required
def reset_password():
    if request.method == "POST":
        data = request.get_json()
        email = data.get("email")
        otp = data.get("otp")
        new_password = data.get("new_password")

        if not email or not otp or not new_password:
            return jsonify({"success": False, "message": "Email, OTP, and new_password required."}), 400

        user = Users.query.filter_by(email=email).first()
        if not user or user.account_type != "customer":
            return jsonify({"success": False, "message": "Invalid email or not a customer."}), 400

        mfa_entry = MFA.query.filter_by(user_id=user.user_id, code=otp).first()
        if not mfa_entry or mfa_entry.expiration < datetime.now():
            return jsonify({"success": False, "message": "Invalid or expired OTP."}), 400

        try:
            user.password_hash = bcrypt.generate_password_hash(new_password).decode("utf-8")
            db.session.delete(mfa_entry)
            db.session.commit()
            return jsonify({"success": True, "message": "Password has been reset."}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "message": f"DB error: {e}"}), 500

    return render_template("reset_password.html")


##############################
#  OTP + ACCOUNT UPDATE      #
##############################

@app.route("/request_otp_page", methods=["GET", "POST"])
@csrf.exempt
@login_required
def request_otp_page():
    if request.method == "POST":
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({"success": False, "message": "Email and password required."}), 400

        if email != current_user.email or not bcrypt.check_password_hash(current_user.password_hash, password):
            return jsonify({"success": False, "message": "Invalid email or password."}), 401

        if current_user.account_type != "customer":
            return jsonify({"success": False, "message": "Only customers can request OTP."}), 403

        verification_code = generate_secure_otp()
        expiration = datetime.now() + timedelta(minutes=10)
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
            return jsonify({"success": True, "message": "Verification code sent to email."}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "message": f"Failed: {e}"}), 500

    return render_template("request_otp_page.html")


@app.route("/otp_verify", methods=["GET", "POST"])
@csrf.exempt
@login_required
def otp_verify():
    if request.method == "POST":
        data = request.get_json()
        otp = data.get("otp")

        if not otp:
            return jsonify({"success": False, "message": "OTP is required."}), 400

        mfa_entry = MFA.query.filter_by(user_id=current_user.user_id, code=otp).first()
        if not mfa_entry or mfa_entry.expiration < datetime.now():
            return jsonify({"success": False, "message": "Invalid or expired OTP."}), 400

        try:
            db.session.delete(mfa_entry)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "message": f"DB error removing OTP: {e}"}), 500

        session["otp_verified"] = True
        return jsonify({"success": True, "message": "OTP verified."}), 200

    return render_template("otp_verify.html")


@app.route("/account_update", methods=["GET", "POST"])
@csrf.exempt
@login_required
def account_update():
    if not session.get("otp_verified"):
        return redirect(url_for("request_otp_page"))
    if current_user.account_type != "customer":
        return redirect(url_for("admin_home"))

    if request.method == "POST":
        data = request.get_json()
        new_email = data.get("new_email")
        new_password = data.get("new_password")
        new_phone = data.get("new_phone")

        if new_email:
            if Users.query.filter(Users.email == new_email, Users.user_id != current_user.user_id).first():
                return jsonify({"success": False, "message": "Email already in use."}), 400
            current_user.email = new_email

        if new_password:
            current_user.password_hash = bcrypt.generate_password_hash(new_password).decode("utf-8")

        if new_phone:
            current_user.phone_number = new_phone

        try:
            db.session.commit()
            session.pop("otp_verified", None)
            return jsonify({"success": True, "message": "Account updated successfully!"}), 200
        except:
            db.session.rollback()
            return jsonify({"success": False, "message": "Database error."}), 500

    return render_template("account_update.html")


##############################
#       REVIEWS ENDPOINT     #
##############################

@app.route("/api/reviews", methods=["GET", "POST"])
@csrf.exempt
@login_required
def api_reviews():
    if current_user.account_type != "customer":
        return jsonify({"success": False, "message": "Unauthorized."}), 403

    if request.method == "POST":
        data = request.get_json()
        rating_header = data.get("rating_header")
        rating_notes = data.get("rating_notes")
        rating_value = data.get("rating_value")

        if not rating_header or not rating_notes or rating_value is None:
            return jsonify({"success": False, "message": "All fields are required."}), 400

        try:
            rating_value = int(rating_value)
            if rating_value < 1 or rating_value > 5:
                return jsonify({"success": False, "message": "Rating must be 1-5."}), 400
        except:
            return jsonify({"success": False, "message": "Invalid rating value."}), 400

        new_review = Ratings(
            user_id=current_user.user_id,
            rating_header=rating_header,
            rating_notes=rating_notes,
            rating_value=rating_value
        )
        try:
            db.session.add(new_review)
            db.session.commit()
            return jsonify({"success": True, "message": "Review submitted."}), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "message": f"DB error: {e}"}), 500

    my_reviews = Ratings.query.filter_by(user_id=current_user.user_id).all()
    data_list = []
    for r in my_reviews:
        data_list.append({
            "rating_header": r.rating_header,
            "rating_notes": r.rating_notes,
            "rating_value": r.rating_value,
            "created_at": r.created_at.strftime("%Y-%m-%d %H:%M:%S")
        })
    return jsonify({"success": True, "reviews": data_list}), 200


##############################
#       EMERGENCY ENDPOINT   #
##############################

@app.route("/api/emergency", methods=["GET", "POST"])
@csrf.exempt
@login_required
def api_emergency():
    if current_user.account_type != "customer":
        return jsonify({"success": False, "message": "Unauthorized."}), 403

    if request.method == "POST":
        data = request.get_json()
        location_details = data.get("location_details")
        distress_notes = data.get("distress_notes")
        if not location_details or not distress_notes:
            return jsonify({"success": False, "message": "All fields are required."}), 400

        new_em = Emergencies(
            user_id=current_user.user_id,
            location_details=location_details,
            distress_notes=distress_notes
        )
        try:
            db.session.add(new_em)
            db.session.commit()
            return jsonify({"success": True, "message": "Emergency log submitted."}), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "message": f"DB error: {e}"}), 500

    my_ems = Emergencies.query.filter_by(user_id=current_user.user_id).all()
    data_list = []
    for em in my_ems:
        data_list.append({
            "emergency_id": em.emergency_id,
            "location_details": em.location_details,
            "distress_notes": em.distress_notes,
            "assigned_employee_id": em.assigned_employee_id,
            "created_at": em.created_at.strftime("%Y-%m-%d %H:%M:%S")
        })
    return jsonify({"success": True, "emergencies": data_list}), 200


##############################
#   CHAT MESSAGES ENDPOINT   #
##############################

@app.route("/api/chat/messages", methods=["GET", "POST"])
@csrf.exempt
@login_required
def api_chat_messages():
    if request.method == "POST":
        data = request.get_json()
        message_text = data.get("message", "").strip()
        if not message_text:
            return jsonify({"success": False, "message": "Message cannot be empty."}), 400

        new_msg = ChatMessages(user_id=current_user.user_id, message=message_text)
        try:
            db.session.add(new_msg)
            db.session.commit()
            return jsonify({"success": True, "message": "Message sent."}), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "message": f"DB error: {e}"}), 500

    msgs = ChatMessages.query.order_by(ChatMessages.timestamp.asc()).all()
    data_list = []
    for m in msgs:
        user_obj = db.session.get(Users, m.user_id)
        username = user_obj.username if user_obj else "Unknown"
        data_list.append({
            "username": username,
            "message": m.message,
            "timestamp": m.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        })
    return jsonify({"success": True, "messages": data_list}), 200


##############################
#   ADMIN: CREATE EMPLOYEE   #
##############################

@app.route("/api/admin/create_employee", methods=["POST"])
@csrf.exempt
@login_required
def admin_create_employee():
    if current_user.account_type not in ["admin", "super_admin"]:
        return jsonify({"success": False, "message": "Unauthorized. Admins only."}), 403

    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    phone_number = data.get("phone_number")

    if not username or not email or not password or not phone_number:
        return jsonify({"success": False, "message": "All fields are required."}), 400

    if Users.query.filter_by(username=username).first():
        return jsonify({"success": False, "message": "Username already exists."}), 400
    if Users.query.filter_by(email=email).first():
        return jsonify({"success": False, "message": "Email already registered."}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
    new_employee = Users(
        username=username,
        email=email,
        password_hash=hashed_password,
        phone_number=phone_number,
        account_type="employee"
    )
    try:
        db.session.add(new_employee)
        db.session.commit()
        return jsonify({"success": True, "message": "Employee created."}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": f"DB error: {e}"}), 500


##############################
#   ADMIN: CREATE ADMIN      #
##############################

@app.route("/api/admin/create_admin", methods=["POST"])
@csrf.exempt
@login_required
def admin_create_admin():
    if current_user.account_type != "super_admin":
        app.logger.warning(f"User {current_user.username} attempted to create an admin without sufficient privileges.")
        return jsonify({"success": False, "message": "Root permission required to create an admin."}), 403

    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    phone_number = data.get("phone_number")

    if not username or not email or not password or not phone_number:
        return jsonify({"success": False, "message": "All fields are required."}), 400

    if Users.query.filter_by(username=username).first():
        return jsonify({"success": False, "message": "Username already exists."}), 400
    if Users.query.filter_by(email=email).first():
        return jsonify({"success": False, "message": "Email already registered."}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
    new_admin = Users(
        username=username,
        email=email,
        password_hash=hashed_password,
        phone_number=phone_number,
        account_type="admin"
    )
    try:
        db.session.add(new_admin)
        db.session.commit()
        app.logger.info(f"Super Admin {current_user.username} created a new Admin: {username}")
        return jsonify({"success": True, "message": "Admin account created successfully."}), 201
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating admin account: {e}")
        return jsonify({"success": False, "message": f"Database error: {e}"}), 500


##############################
#   ADMIN: ASSIGN/UNASSIGN   #
##############################

@app.route("/api/admin/assign_emergency", methods=["POST"])
@csrf.exempt
@login_required
def admin_assign_emergency():
    if current_user.account_type not in ["admin", "super_admin"]:
        return jsonify({"success": False, "message": "Unauthorized. Admins only."}), 403

    data = request.get_json()
    emergency_id = data.get("emergency_id")
    employee_id = data.get("employee_id")

    if not emergency_id or not employee_id:
        return jsonify({"success": False, "message": "emergency_id and employee_id required"}), 400

    emergency = db.session.get(Emergencies, emergency_id)
    if not emergency:
        return jsonify({"success": False, "message": "Emergency not found."}), 404

    employee_user = db.session.get(Users, employee_id)
    if not employee_user or employee_user.account_type != "employee":
        return jsonify({"success": False, "message": "User is not an employee."}), 400

    if employee_user.is_locked:
        return jsonify({"success": False, "message": "Cannot assign work to a locked employee."}), 403

    if emergency.assigned_employee_id is not None:
        return jsonify({"success": False, "message": "Already assigned."}), 400

    updated = update_assigned_employee_id(emergency.distress_notes, new_employee_id=employee_id)
    emergency.distress_notes = updated
    emergency.assigned_employee_id = employee_id

    distress_notes_clean = updated.split("[ASSIGNED_EMPLOYEE=")[0].strip() if updated else "N/A"

    try:
        db.session.commit()
        customer_user = db.session.get(Users, emergency.user_id)
        send_assignment_email_to_employee(
            employee=employee_user,
            customer=customer_user,
            emergency_id=emergency.emergency_id,
            location_details=emergency.location_details,
            distress_notes=distress_notes_clean,
            admin_user=current_user,
            assigned=True
        )
        send_assignment_email_to_customer(
            customer=customer_user,
            emergency_id=emergency.emergency_id,
            location_details=emergency.location_details,
            distress_notes=distress_notes_clean,
            employee_username=employee_user.username,
            employee_phone=employee_user.phone_number,
            employee_email=employee_user.email,
            assigned=True
        )
        return jsonify({"success": True, "message": "Assigned successfully."}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Assign Emergency Error: {e}")
        app.logger.error(traceback.format_exc())
        return jsonify({"success": False, "message": f"DB error: {e}"}), 500


@app.route("/api/admin/unassign_emergency", methods=["POST"])
@csrf.exempt
@login_required
def admin_unassign_emergency():
    if current_user.account_type not in ["admin", "super_admin"]:
        return jsonify({"success": False, "message": "Unauthorized. Admins only."}), 403

    data = request.get_json()
    emergency_id = data.get("emergency_id")
    if not emergency_id:
        return jsonify({"success": False, "message": "emergency_id required"}), 400

    emergency = db.session.get(Emergencies, emergency_id)
    if not emergency:
        return jsonify({"success": False, "message": "Emergency not found."}), 404

    current_assignee = emergency.assigned_employee_id
    if current_assignee is None:
        return jsonify({"success": False, "message": "No assigned employee."}), 400

    updated = update_assigned_employee_id(emergency.distress_notes, new_employee_id=None)
    emergency.distress_notes = updated
    emergency.assigned_employee_id = None

    distress_notes_clean = updated.split("[ASSIGNED_EMPLOYEE=")[0].strip() if updated else "N/A"

    try:
        db.session.commit()
        employee_user = db.session.get(Users, current_assignee)
        customer_user = db.session.get(Users, emergency.user_id)
        if employee_user:
            send_assignment_email_to_employee(
                employee=employee_user,
                customer=customer_user,
                emergency_id=emergency.emergency_id,
                location_details=emergency.location_details,
                distress_notes=distress_notes_clean,
                admin_user=current_user,
                assigned=False
            )
        send_assignment_email_to_customer(
            customer=customer_user,
            emergency_id=emergency.emergency_id,
            location_details=emergency.location_details,
            distress_notes=distress_notes_clean,
            assigned=False
        )
        return jsonify({"success": True, "message": "Unassigned successfully."}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Unassign Emergency Error: {e}")
        app.logger.error(traceback.format_exc())
        return jsonify({"success": False, "message": f"DB error: {e}"}), 500


##############################
#  ADMIN: DELETE EMPLOYEE    #
##############################

@app.route("/api/admin/delete_employee", methods=["POST"])
@csrf.exempt
@login_required
def admin_delete_employee():
    if current_user.account_type not in ["admin", "super_admin"]:
        return jsonify({"success": False, "message": "Unauthorized. Admins only."}), 403

    data = request.get_json()
    employee_id = data.get("employee_id")
    if not employee_id:
        return jsonify({"success": False, "message": "employee_id required"}), 400

    user_to_delete = db.session.get(Users, employee_id)
    if not user_to_delete or user_to_delete.account_type not in ["employee", "admin"]:
        return jsonify({"success": False, "message": "User is not an employee/admin or does not exist."}), 400

    # Block deletion if locked
    if user_to_delete.is_locked:
        return jsonify({"success": False, "message": "Cannot delete a locked account. Unlock first."}), 403

    # Prevent super_admin from deleting themselves
    if user_to_delete.account_type == "super_admin" and user_to_delete.user_id == current_user.user_id:
        return jsonify({"success": False, "message": "Super Admin cannot delete themselves."}), 403

    try:
        tables = ["mfa", "chat_messages", "ratings", "emergencies", "users"]
        with db.engine.connect() as connection:
            trans = connection.begin()
            try:
                for tbl in tables:
                    query = text(f"DELETE FROM {tbl} WHERE user_id = :uid")
                    connection.execute(query, {"uid": employee_id})
                trans.commit()
            except:
                trans.rollback()
                raise

        return jsonify({"success": True, "message": f"Employee/Admin (ID={employee_id}) removed."}), 200
    except Exception as e:
        app.logger.error(f"Delete Employee/Admin Error: {e}")
        app.logger.error(traceback.format_exc())
        return jsonify({"success": False, "message": f"Database error: {e}"}), 500


##############################
#   ADMIN: UPDATE STAFF      #
##############################

@app.route("/api/admin/update_staff/<int:staff_id>", methods=["POST"])
@csrf.exempt
@login_required
def admin_update_staff(staff_id):
    if current_user.account_type not in ["admin", "super_admin"]:
        return jsonify({"success": False, "message": "Unauthorized. Admins only."}), 403

    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    phone_number = data.get("phone_number")
    is_locked = data.get("is_locked")  # Toggling from JS

    user = db.session.get(Users, staff_id)
    if not user or user.account_type not in ["employee", "admin"]:
        return jsonify({"success": False, "message": "User not found or not an employee/admin."}), 404

    # If user is locked, only super_admin can "unlock" them
    if user.is_locked:
        if current_user.account_type == "super_admin" and is_locked is False:
            # They want to unlock
            user.is_locked = False
            # Keep the rest of data updates minimal or disallowed
            db.session.commit()
            return jsonify({"success": True, "message": "Locked account unlocked by super_admin."}), 200
        else:
            return jsonify({"success": False, "message": "Cannot update locked account (unless super_admin unlocking)."}), 403

    # Prevent super_admin from modifying themselves if they are super_admin

    if user.account_type == "super_admin" and user.user_id == current_user.user_id:
        return jsonify({"success": False, "message": "Super Admin cannot modify their own account."}), 403

    # Normal updates if user is not locked
    if username:
        user.username = username
    if email:
        # Check if the new email is already taken
        existing = Users.query.filter(Users.email == email, Users.user_id != staff_id).first()
        if existing:
            return jsonify({"success": False, "message": "Email already in use."}), 400
        user.email = email
    if password:
        user.password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
    if phone_number:
        user.phone_number = phone_number

    # If super_admin toggles lock => lock the user
    if is_locked is not None and current_user.account_type == "super_admin":
        # If is_locked == True => lock the user
        # If is_locked == False => means "unlock" but we handled that above if already locked
        if user.account_type == "super_admin":
            return jsonify({"success": False, "message": "Cannot lock/unlock another Super Admin."}), 403
        # Lock them if is_locked==True
        if is_locked is True:
            user.is_locked = True
            user.session_token = None  # Invalidate session

    try:
        db.session.commit()
        return jsonify({"success": True, "message": "Staff updated successfully."}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": f"DB error: {e}"}), 500
##############################
#       DELETE ACCOUNT       #
##############################

@app.route("/api/delete_account", methods=["POST"])
@csrf.exempt
@login_required
def api_delete_account():
    try:
        user_id = current_user.user_id
        tables = ["mfa", "chat_messages", "ratings", "emergencies", "users"]
        with db.engine.connect() as connection:
            trans = connection.begin()
            try:
                for tbl in tables:
                    query = text(f"DELETE FROM {tbl} WHERE user_id = :uid")
                    connection.execute(query, {"uid": user_id})
                trans.commit()
            except:
                trans.rollback()
                raise

        logout_user()
        session.clear()
        return jsonify({"success": True, "message": "Account deleted successfully."}), 200
    except Exception as e:
        return jsonify({"success": False, "message": f"Database error: {e}"}), 500



##############################
#      ADMIN SETUP ROUTE     #
##############################

@app.route("/admin_setup", methods=["GET", "POST"])
def admin_setup():
    existing_admin = Users.query.filter_by(account_type="admin").first()
    if existing_admin:
        admin_users = Users.query.filter_by(account_type="admin").all()
        admin_emails = [admin.email for admin in admin_users]
        admin_contact_email = ", ".join(admin_emails)
        flash(f"An admin account already exists. Please contact {admin_contact_email} for admin account setup.", "info")
        return redirect(url_for("login_page"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        phone_number = request.form.get("phone_number", "").strip()
        root_password = request.form.get("root_password", "").strip()

        if not username or not email or not password or not phone_number or not root_password:
            flash("All fields are required.", "error")
            return redirect(url_for("admin_setup"))

        expected_root_password = os.getenv("ROOT_PASSWORD", "")
        if root_password != expected_root_password:
            flash("Invalid root password.", "error")
            return redirect(url_for("admin_setup"))

        if Users.query.filter_by(username=username).first():
            flash("Username already exists!", "error")
            return redirect(url_for("admin_setup"))
        if Users.query.filter_by(email=email).first():
            flash("Email already registered.", "error")
            return redirect(url_for("admin_setup"))

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        new_admin = Users(
            username=username,
            email=email,
            password_hash=hashed_password,
            phone_number=phone_number,
            account_type="admin"
        )
        try:
            db.session.add(new_admin)
            db.session.commit()
            flash("Admin account created successfully! You can now log in as admin.", "success")
            return redirect(url_for("login_page"))
        except Exception as e:
            db.session.rollback()
            flash(f"Database error: {e}", "error")
            return redirect(url_for("admin_setup"))

    return render_template("admin_setup.html")


##############################
#   SUPER ADMIN ROUTES       #
##############################

@app.route("/api/elevate_super_admin", methods=["POST"])
@csrf.exempt
@login_required
def elevate_super_admin_route():
    if current_user.account_type != "admin":
        return jsonify({"success": False, "message": "Unauthorized. Admins only."}), 403

    attempts = session.get("elevate_super_admin_attempts", 0)
    if attempts >= 3:
        return jsonify({"success": False, "message": "Max attempts reached. Please contact an existing super admin."}), 403

    existing_super_admin = Users.query.filter_by(account_type="super_admin").first()
    if existing_super_admin:
        return jsonify({"success": False, "message": "A super admin already exists."}), 403

    data = request.get_json()
    root_password = data.get("root_password", "").strip()

    if not root_password:
        return jsonify({"success": False, "message": "Root password is required."}), 400

    expected_root_password = os.getenv("ROOT_PASSWORD", "")

    if root_password == expected_root_password:
        try:
            current_user.account_type = "super_admin"
            db.session.commit()
            session["elevate_super_admin_attempts"] = 0
            app.logger.info(f"User {current_user.username} elevated to super_admin at {datetime.now()}")
            return jsonify({"success": True, "message": "Elevated to super admin."}), 200
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Database error during elevation: {e}")
            app.logger.error(traceback.format_exc())
            return jsonify({"success": False, "message": f"Database error: {e}"}), 500
    else:
        attempts += 1
        session["elevate_super_admin_attempts"] = attempts
        if attempts >= 3:
            return jsonify({"success": False, "message": "Incorrect root password. Max attempts reached."}), 403
        else:
            return jsonify({"success": False, "message": "Incorrect root password."}), 401

@app.route("/api/admin/lock_account", methods=["POST"])
@csrf.exempt
@login_required
def admin_lock_account():
    if current_user.account_type not in ["admin", "super_admin"]:
        return jsonify({"success": False, "message": "Unauthorized. Admins only."}), 403

    data = request.get_json()
    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"success": False, "message": "user_id is required."}), 400

    user = db.session.get(Users, user_id)
    if not user or user.account_type not in ["employee", "admin"]:
        return jsonify({"success": False, "message": "User not found or not an employee/admin."}), 404

    # Prevent super_admin from locking themselves
    if user.account_type == "super_admin" and user.user_id == current_user.user_id:
        return jsonify({"success": False, "message": "Super Admin cannot lock their own account."}), 403

    if user.is_locked:
        return jsonify({"success": False, "message": "Account is already locked."}), 400

    # Lock the account + invalidate session
    user.is_locked = True
    user.session_token = None  # Force logout if user is still active

    try:
        # Gather all emergencies this user is assigned to
        assigned_emergencies = Emergencies.query.filter_by(assigned_employee_id=user.user_id).all()

        # For each emergency, unassign + email the customers
        for em in assigned_emergencies:
            em.assigned_employee_id = None

            # Email the customer to let them know the employee is no longer tracking
            customer_obj = db.session.get(Users, em.user_id)
            if customer_obj:
                # Provide minimal info
                send_assignment_email_to_customer(
                    customer=customer_obj,
                    emergency_id=em.emergency_id,
                    location_details=em.location_details,
                    distress_notes=em.distress_notes if em.distress_notes else "",
                    assigned=False
                )

        # Commit DB changes so unassignments take effect
        db.session.commit()

        # Finally, send an HTML email to the employee about the lock
        send_employee_locked_email(user)

        return jsonify({
            "success": True,
            "message": (
                "Account locked successfully. "
                "All assigned emergencies have been unassigned and notifications sent."
            )
        }), 200
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Database error during account lock: {str(e)}")
        return jsonify({"success": False, "message": "Server error. Please try again later."}), 500

@app.route("/api/admin/unlock_account", methods=["POST"])
@csrf.exempt
@login_required
def admin_unlock_account():
    if current_user.account_type not in ["admin", "super_admin"]:
        return jsonify({"success": False, "message": "Unauthorized. Admins only."}), 403

    data = request.get_json()
    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"success": False, "message": "user_id is required."}), 400

    user = db.session.get(Users, user_id)
    if not user or user.account_type not in ["employee", "admin"]:
        return jsonify({"success": False, "message": "User not found or not an employee/admin."}), 404

    if not user.is_locked:
        return jsonify({"success": False, "message": "Account is not locked."}), 400

    user.is_locked = False

    try:
        db.session.commit()

        # Send unlock email
        try:
            html_content = render_template(
                "emails/account_unlocked.html",
                user=user,
                current_year=datetime.utcnow().year
            )
            send_email(
                to_address=user.email,
                subject="Your Account Has Been Unlocked",
                body=html_content,
                html=True
            )
            app.logger.info(f"Unlock email sent to {user.username} ({user.email}).")
        except Exception as e:
            app.logger.error(f"Failed to send unlock email to {user.username}: {e}")

        return jsonify({"success": True, "message": "Account unlocked successfully."}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Database error during account unlock: {str(e)}")
        return jsonify({"success": False, "message": "Server error. Please try again later."}), 500


#########################
#   EMAIL FUNCTIONS     #
#########################

def send_verification_email(to_email, username, verification_code):
    subject = "Cave Country Canoes Account Verification Code"
    body = f"""\
Dear {username},

Your verification code is {verification_code}.

- Cave Country Canoes
"""
    send_email(to_email, subject, body, html=False)


def send_assignment_email_to_employee(
        employee,
        customer,
        emergency_id=None,
        location_details=None,
        distress_notes=None,
        admin_user=None,
        assigned=True
):
    if assigned:
        subject = "New Emergency Assignment"
        app.logger.debug(f"Sending assignment email to employee {employee.username} with distress_notes: {distress_notes}")
        # Render a hypothetical HTML template if there is one, else basic text
        body = f"""\
Dear {employee.username},

You have been assigned to track the following customer's emergency.

Emergency Details:
- Emergency Log ID: {emergency_id if emergency_id else 'N/A'}
- Location Details: {location_details if location_details else 'N/A'}
- Distress Notes: {distress_notes if distress_notes else 'N/A'}

Customer Details:
- Name: {customer.username if customer else 'Unknown'}
- Phone: {customer.phone_number if customer else 'N/A'}
- Email: {customer.email if customer else 'N/A'}

Assigned by Admin:
- Username: {admin_user.username if admin_user else 'N/A'}
- Phone: {admin_user.phone_number if admin_user else 'N/A'}
- Email: {admin_user.email if admin_user else 'N/A'}

- Cave Country Canoes
"""
    else:
        subject = "Emergency Tracking Termination Notice"
        app.logger.debug(f"Sending termination email to employee {employee.username} with distress_notes: {distress_notes}")
        body = f"""\
Dear {employee.username},

An admin ({admin_user.username if admin_user else 'N/A'}) has terminated your tracking of:

Emergency Details:
- Emergency Log ID: {emergency_id if emergency_id else 'N/A'}
- Location Details: {location_details if location_details else 'N/A'}
- Distress Notes: {distress_notes if distress_notes else 'N/A'}

Customer Details:
- Name: {customer.username if customer else 'Unknown'}
- Phone: {customer.phone_number if customer else 'N/A'}
- Email: {customer.email if customer else 'N/A'}

- Cave Country Canoes
"""
    send_email(employee.email, subject, body, html=False)

def send_employee_not_tracking_email(customer, employee, emergency_id):
    html_content = render_template(
        "emails/employee_not_tracking.html",
        customer=customer,
        employee=employee,
        emergency_id=emergency_id,
        current_year=datetime.now().year
    )
    send_email(
        to_address=customer.email,
        subject="Cave Country Canoes Employee No Longer Tracking Your Emergency",
        body=html_content,
        html=True
    )

def send_admin_locked_email(admin_user):
    html_content = render_template(
        "emails/admin_locked.html",
        admin=admin_user,
        current_year=datetime.now().year
    )
    send_email(
        to_address=admin_user.email,
        subject="Admin Account Locked",
        body=html_content,
        html=True
    )

def send_account_unlocked_email(user):
    html_content = render_template(
        "emails/account_unlocked.html",
        user=user,
        current_year=datetime.now().year
    )
    send_email(
        to_address=user.email,
        subject="Your Cave Country Canoes Account Has Been Unlocked",
        body=html_content,
        html=True
    )


def send_assignment_email_to_customer(
        customer,
        emergency_id=None,
        location_details=None,
        distress_notes=None,
        employee_username=None,
        employee_phone=None,
        employee_email=None,
        assigned=True
):
    if assigned:
        subject = "Emergency Tracking Assignment"
        app.logger.debug(f"Sending assignment email to customer {customer.username} with distress_notes: {distress_notes}")
        body = f"""\
Dear {customer.username},

An employee has been assigned to your emergency log.

Emergency Details:
- Emergency Log ID: {emergency_id if emergency_id else 'N/A'}
- Location Details: {location_details if location_details else 'N/A'}
- Distress Notes: {distress_notes if distress_notes else 'N/A'}

Employee Details:
- Username: {employee_username if employee_username else 'N/A'}
- Phone Number: {employee_phone if employee_phone else 'N/A'}
- Email: {employee_email if employee_email else 'N/A'}

They may reach out to you soon if needed.

- Cave Country Canoes
"""
    else:
        subject = "Emergency Tracking Termination"
        app.logger.debug(f"Sending termination email to customer {customer.username} with distress_notes: {distress_notes}")
        body = f"""\
Dear {customer.username},

Your assigned employee has been unassigned by an admin.
If you have any questions, please reach out via chat.

- Cave Country Canoes
"""
    send_email(customer.email, subject, body, html=False)

def send_employee_locked_email(employee):
    """
    Sends an HTML email to the locked employee, letting them know
    that their account has been locked and all emergencies unassigned.
    """
    subject = "Your Account Has Been Locked"
    current_year = datetime.now().year

    # Render the HTML template with context
    html_content = render_template(
        "emails/employee_locked.html",
        employee=employee,
        current_year=current_year
    )

    # Now use existing send_email to send HTML content
    send_email(
        to_address=employee.email,
        subject=subject,
        body=html_content,
        html=True  # Indicate this is HTML
    )


def send_email(to_address, subject, body, html=False):
    email_sender = app.config['MAIL_USERNAME']
    email_password = app.config['MAIL_PASSWORD']
    em = EmailMessage()
    em["From"] = email_sender
    em["To"] = to_address
    em["Subject"] = subject
    em.set_charset('utf-8')

    if html:
        em.add_alternative(body, subtype='html')
    else:
        em.set_content(body)

    context = ssl.create_default_context()
    try:
        with smtplib.SMTP_SSL(app.config['MAIL_SERVER'], app.config['MAIL_PORT'], context=context) as smtp:
            smtp.login(email_sender, email_password)
            smtp.send_message(em)
        app.logger.info(f"Email sent to {to_address} with subject '{subject}'.")
    except Exception as e:
        app.logger.error(f"Failed to send email to {to_address}: {e}")
        app.logger.error(traceback.format_exc())


#########################
#  SESSION VALIDATION   #
#########################

@app.before_request
def validate_session_token():
    if current_user.is_authenticated:
        session_token = session.get('session_token')
        if not session_token or current_user.session_token != session_token:
            logout_user()
            session.clear()
            flash("Your session has been terminated. Please log in again.", "warning")
            return redirect(url_for("login_page"))


if __name__ == "__main__":
    local_ip = get_local_ip()
    print(f"Running on http://{local_ip}:5000")
    app.run(host=local_ip, port=5000, debug=True)