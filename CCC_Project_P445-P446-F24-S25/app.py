import hashlib
import socket
import secrets
import smtplib
import ssl
import traceback
import os
from datetime import datetime, timedelta
from email.message import EmailMessage
from flask import (
    Flask, render_template, redirect, url_for,
    request, jsonify, session, flash, make_response
)
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager, login_user, current_user,
    logout_user, login_required, UserMixin
)
from flask_mail import Mail
from dotenv import load_dotenv
from urllib.parse import quote_plus
from sqlalchemy import text
from sqlalchemy.exc import SAWarning
from flask_wtf import CSRFProtect

import warnings

warnings.filterwarnings("ignore", category=SAWarning)  # Suppress SQLAlchemy warnings

# Load environment variables
load_dotenv()

#########################
#      CONFIGURATION    #
#########################

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "defaultsecretkey")
    SQLALCHEMY_DATABASE_URI = (
        f"mysql+pymysql://{os.getenv('DB_USER')}:{quote_plus(os.getenv('DB_PASSWORD', ''))}"
        f"@{os.getenv('DB_HOST')}/{os.getenv('DB_NAME')}"
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

env = os.getenv("FLASK_ENV", "development")
app_config = ProductionConfig if env == "production" else DevelopmentConfig

#########################
#   APP & EXTENSIONS    #
#########################

app = Flask(__name__)
app.config.from_object(app_config)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
login_manager.login_view = "login_page"
login_manager.login_message_category = "info"

# Mail configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 465))
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = app.config['MAIL_USERNAME']

mail = Mail(app)

# Enable CSRF protection
csrf = CSRFProtect(app)

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
    except Exception:
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
        distress_text = distress_text + ("\n" + marker if distress_text else marker)
    return distress_text.strip()

def generate_secure_otp():
    random_bytes = secrets.token_bytes(16)
    return hashlib.sha256(random_bytes).hexdigest()[:6].upper()

def get_local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
    except Exception:
        local_ip = "127.0.0.1"
    return local_ip

#########################
#  SESSION TOKEN UTILS  #
#########################

def generate_unique_session_token():
    while True:
        token = secrets.token_hex(32)
        existing_user = Users.query.filter_by(session_token=token).first()
        if not existing_user:
            return token

##############################
#         MODELS             #
##############################

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
    session_token = db.Column(db.String(64), nullable=True, unique=True)
    created_at = db.Column(db.DateTime, default=datetime.now())
    email_verified = db.Column(db.Boolean, default=False, nullable=False)

    @property
    def id(self):
        return self.user_id

    assigned_emergencies = db.relationship(
        "Emergencies", back_populates="assigned_employee",
        lazy=True, foreign_keys="Emergencies.assigned_employee_id"
    )
    emergencies_created = db.relationship(
        "Emergencies", back_populates="customer",
        lazy=True, foreign_keys="Emergencies.user_id"
    )
    chat_messages = db.relationship("ChatMessages", back_populates="user", lazy=True)
    ratings = db.relationship("Ratings", back_populates="user", lazy=True)

    def verify_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class EmailVerification(db.Model):
    __tablename__ = "email_verifications"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False, unique=True)
    token = db.Column(db.String(128), nullable=False, unique=True)
    expiration = db.Column(db.DateTime, nullable=False)

    user = db.relationship("Users")

class PendingUser(db.Model):
    __tablename__ = "pending_users"
    pending_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    account_type = db.Column(db.String(20), nullable=False, default="customer")
    created_at = db.Column(db.DateTime, default=datetime.now())
    token = db.Column(db.String(128), nullable=False, unique=True)
    token_expiration = db.Column(db.DateTime, nullable=False)

class Ratings(db.Model):
    __tablename__ = "ratings"
    rating_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer,
        db.ForeignKey("users.user_id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False
    )
    rating_header = db.Column(db.String(100), nullable=False)
    rating_notes = db.Column(db.Text, nullable=False)
    rating_value = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now())

    user = db.relationship("Users", back_populates="ratings")

class Emergencies(db.Model):
    __tablename__ = "emergencies"
    emergency_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer,
        db.ForeignKey("users.user_id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False
    )
    location_details = db.Column(db.Text, nullable=True)
    distress_notes = db.Column(db.Text, nullable=True)
    assigned_employee_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now())

    assigned_employee = db.relationship(
        "Users", back_populates="assigned_emergencies",
        foreign_keys=[assigned_employee_id]
    )
    customer = db.relationship(
        "Users", back_populates="emergencies_created",
        foreign_keys=[user_id]
    )

class ChatMessages(db.Model):
    __tablename__ = "chat_messages"
    message_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer,
        db.ForeignKey("users.user_id", ondelete="CASCADE", onupdate="CASCADE"),
        nullable=False
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

    user = db.relationship("Users")

##############################
#       CONTEXT PROCESSOR    #
##############################

@app.context_processor
def inject_session_token():
    if current_user.is_authenticated:
        return dict(session_token=current_user.session_token)
    return dict(session_token='')

##############################
#       ROUTES / VIEWS       #
##############################

@app.route("/")
def index():
    return redirect(url_for("login_page"))

@app.route("/login_page", methods=["GET", "POST"])
def login_page():
    if current_user.is_authenticated:
        if current_user.account_type in ["admin", "super_admin"]:
            return redirect(url_for("admin_home", st=current_user.session_token))
        elif current_user.account_type == "customer":
            return redirect(url_for("customer_dashboard", st=current_user.session_token))
        elif current_user.account_type == "employee":
            return redirect(url_for("employee_home", st=current_user.session_token))

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = Users.query.filter_by(email=email).first()
        if user and not user.is_locked and user.verify_password(password):
            user.session_token = generate_unique_session_token()
            db.session.commit()
            login_user(user)
            session['session_token'] = user.session_token
            flash("Logged in successfully!", "success")
            if user.account_type in ["admin", "super_admin"]:
                return redirect(url_for("admin_home", st=user.session_token))
            elif user.account_type == "customer":
                return redirect(url_for("customer_dashboard", st=user.session_token))
            elif user.account_type == "employee":
                return redirect(url_for("employee_home", st=user.session_token))
        elif user and user.is_locked:
            flash("Your account is locked. Please contact support.", "danger")
        else:
            flash("Invalid email or password.", "danger")
    return render_template("login.html")

@app.route("/signup_page", methods=["GET", "POST"])
def signup_page():
    if current_user.is_authenticated:
        if current_user.account_type in ["admin", "super_admin"]:
            return redirect(url_for("admin_home", st=current_user.session_token))
        elif current_user.account_type == "customer":
            return redirect(url_for("customer_dashboard", st=current_user.session_token))
        elif current_user.account_type == "employee":
            return redirect(url_for("employee_home", st=current_user.session_token))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password")
        phone_number = request.form.get("phone_number", "").strip()

        if not username or not email or not password or not phone_number:
            flash("All fields are required.", "danger")
            return render_template("Customer/signup.html")

        if Users.query.filter_by(username=username).first() or PendingUser.query.filter_by(username=username).first():
            flash("Username already exists!", "danger")
            return render_template("Customer/signup.html")
        if Users.query.filter_by(email=email).first() or PendingUser.query.filter_by(email=email).first():
            flash("Email already registered.", "danger")
            return render_template("Customer/signup.html")

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        token = secrets.token_urlsafe(32)
        expiration = datetime.now() + timedelta(hours=24)

        new_pending = PendingUser(
            username=username,
            email=email,
            password_hash=hashed_password,
            phone_number=phone_number,
            account_type="customer",
            token=token,
            token_expiration=expiration
        )
        try:
            db.session.add(new_pending)
            db.session.commit()

            verification_link = url_for("verify_email", token=token, _external=True)

            html_content = render_template(
                "emails/new_customer_credentials.html",
                username=username,
                email=email,
                verification_link=verification_link
            )

            send_email(email, "Verify Your Email", html_content, html=True)
            flash("Account created successfully! Please check your email to verify your account.", "success")
            return redirect(url_for("login_page"))
        except Exception as e:
            db.session.rollback()
            flash(f"Database error: {e}", "danger")
            return render_template("Customer/signup.html")
    return render_template("Customer/signup.html")

@app.route("/customer_dashboard")
@login_required
def customer_dashboard():
    if current_user.account_type == "customer":
        return render_template("Customer/customer_dashboard.html", username=current_user.username)
    elif current_user.account_type in ["admin", "super_admin"]:
        return redirect(url_for("admin_home", st=current_user.session_token))
    else:
        return redirect(url_for("employee_home", st=current_user.session_token))

@app.route("/reviews_page")
@login_required
def reviews_page():
    if current_user.account_type != "customer":
        if current_user.account_type in ["admin", "super_admin"]:
            return redirect(url_for("admin_home", st=current_user.session_token))
        else:
            return redirect(url_for("employee_home", st=current_user.session_token))
    return render_template("Customer/customer_reviews.html")

@app.route("/submit_log_page", methods=["GET", "POST"])
@login_required
def submit_log_page():
    if current_user.account_type != "customer":
        if current_user.account_type in ["admin", "super_admin"]:
            return redirect(url_for("admin_home", st=current_user.session_token))
        else:
            return redirect(url_for("employee_home", st=current_user.session_token))
    if request.method == "POST":
        location_details = request.form.get("location_details").strip()
        distress_notes = request.form.get("distress_notes").strip()
        if not location_details or not distress_notes:
            flash("All fields are required.", "danger")
            return render_template("Customer/customer_submit_log.html")
        new_emergency = Emergencies(
            user_id=current_user.user_id,
            location_details=location_details,
            distress_notes=distress_notes
        )
        try:
            db.session.add(new_emergency)
            db.session.commit()
            flash("Emergency log submitted successfully!", "success")
            return redirect(url_for("customer_dashboard", st=current_user.session_token))
        except Exception as e:
            db.session.rollback()
            flash(f"Database error: {e}", "danger")
            return render_template("Customer/customer_submit_log.html")
    return render_template("Customer/customer_submit_log.html")

@app.route("/chat")
@login_required
def chat():
    return render_template("Customer/customer_chat.html", username=current_user.username, account_type=current_user.account_type)

##############################
#   ADMIN DASHBOARD ROUTES   #
##############################

@app.route("/admin/home")
@login_required
def admin_home():
    if current_user.account_type not in ["admin", "super_admin"]:
        if current_user.account_type == "employee":
            return redirect(url_for("employee_home", st=current_user.session_token))
        return redirect(url_for("customer_dashboard", st=current_user.session_token))
    total_customers = Users.query.filter_by(account_type="customer").count()
    total_employees = Users.query.filter_by(account_type="employee").count()
    total_emergencies = Emergencies.query.count()
    unresolved_emergencies = Emergencies.query.filter(Emergencies.assigned_employee_id == None).count()
    stats = {
        "total_customers": total_customers,
        "total_employees": total_employees,
        "total_emergencies": total_emergencies,
        "unresolved_emergencies": unresolved_emergencies
    }
    return render_template("Admin/admin_home.html", stats=stats)

@app.route("/admin/manage_staff")
@login_required
def admin_manage_staff():
    if current_user.account_type not in ["admin", "super_admin"]:
        if current_user.account_type == "employee":
            return redirect(url_for("employee_home", st=current_user.session_token))
        return redirect(url_for("customer_dashboard", st=current_user.session_token))
    employees = Users.query.filter_by(account_type="employee").all()
    admins = Users.query.filter_by(account_type="admin").all() if current_user.account_type == "super_admin" else []
    return render_template("Admin/admin_manage_staff.html", employees=employees, admins=admins)

@app.route("/admin/manage_emergencies")
@login_required
def admin_manage_emergencies():
    if current_user.account_type not in ["admin", "super_admin"]:
        if current_user.account_type == "employee":
            return redirect(url_for("employee_home", st=current_user.session_token))
        return redirect(url_for("customer_dashboard", st=current_user.session_token))
    all_ems = Emergencies.query.all()
    employees = Users.query.filter_by(account_type="employee").all()
    data_emergencies = []
    for em in all_ems:
        assigned_user = Users.query.get(em.assigned_employee_id) if em.assigned_employee_id else None
        customer_obj = Users.query.get(em.user_id)
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
    return render_template("Admin/admin_manage_emergencies.html", emergencies=data_emergencies, employees=employees)

@app.route("/admin/chat")
@login_required
def admin_chat():
    if current_user.account_type not in ["admin", "super_admin"]:
        if current_user.account_type == "employee":
            return redirect(url_for("employee_home", st=current_user.session_token))
        return redirect(url_for("customer_dashboard", st=current_user.session_token))
    return render_template("Admin/admin_chat.html", username=current_user.username, account_type=current_user.account_type)

##############################
#  SIGNUP, LOGIN, LOGOUT     #
##############################

@app.route("/api/signup", methods=["POST"])
def api_signup():
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    phone_number = data.get("phone_number")

    if not username or not email or not password or not phone_number:
        return jsonify({"success": False, "message": "All fields are required."}), 400

    if Users.query.filter_by(username=username).first() or PendingUser.query.filter_by(username=username).first():
        return jsonify({"success": False, "message": "Username already exists!"}), 400
    if Users.query.filter_by(email=email).first() or PendingUser.query.filter_by(email=email).first():
        return jsonify({"success": False, "message": "Email already registered."}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

    try:
        token = secrets.token_urlsafe(32)
        expiration = datetime.now() + timedelta(hours=24)

        pending = PendingUser(
            username=username,
            email=email,
            password_hash=hashed_password,
            phone_number=phone_number,
            account_type="customer",
            token=token,
            token_expiration=expiration
        )
        db.session.add(pending)
        db.session.commit()

        verification_link = url_for("verify_email", token=token, _external=True)

        html_content = render_template(
            "emails/new_customer_credentials.html",
            username=username,
            email=email,
            verification_link=verification_link
        )

        send_email(email, "Verify Your Email", html_content, html=True)
        app.logger.info(f"Verification email sent to {email}.")

        return jsonify({
            "success": True,
            "message": "Account created successfully! Please check your email to verify your account."
        }), 201

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Signup error: {e}")
        return jsonify({"success": False, "message": f"Database error: {e}"}), 500

@app.route("/verify_email/<token>", methods=["GET"])
def verify_email(token):
    pending = PendingUser.query.filter_by(token=token).first()
    if not pending:
        flash("Invalid or expired verification token.", "danger")
        return redirect(url_for("signup_page"))

    if pending.token_expiration < datetime.now():
        db.session.delete(pending)
        db.session.commit()
        flash("Verification token has expired. Please sign up again.", "danger")
        return redirect(url_for("signup_page"))

    try:
        new_user = Users(
            username=pending.username,
            email=pending.email,
            password_hash=pending.password_hash,
            phone_number=pending.phone_number,
            account_type=pending.account_type,
            email_verified=True
        )
        db.session.add(new_user)
        db.session.delete(pending)
        db.session.commit()
        flash("Your email has been verified. You can now log in.", "success")
    except Exception as e:
        db.session.rollback()
        flash("An error occurred during email verification. Please try again.", "danger")
        app.logger.error(f"Email verification error: {e}")
    return redirect(url_for("login_page"))

@app.route("/api/login", methods=["POST"])
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
            user.session_token = generate_unique_session_token()
            db.session.commit()
            login_user(user, remember=False)
            session['session_token'] = user.session_token
            app.logger.info(f"User {user.username} logged in successfully.")
            return jsonify({"success": True, "message": "Logged in successfully!", "account_type": user.account_type}), 200
        else:
            app.logger.warning(f"Failed login attempt for user {user.username}. Incorrect password.")
            return jsonify({"success": False, "message": "Invalid email or password."}), 401
    else:
        app.logger.warning(f"Failed login attempt for non-existent email: {email}.")
        return jsonify({"success": False, "message": "Invalid email or password."}), 401

@app.route("/api/logout", methods=["GET", "POST"])
@login_required
def logout():
    if current_user.account_type == "super_admin":
        current_user.account_type = "admin"
    current_user.session_token = None
    db.session.commit()
    logout_user()
    session.clear()
    if request.accept_mimetypes.best == "application/json":
        return jsonify({"success": True, "message": "Logged out successfully."}), 200
    else:
        flash("You have been logged out.", "info")
        return redirect(url_for("login_page"))

##############################
#   FORGOT PASSWORD          #
##############################

@app.route("/forgot_password", methods=["GET", "POST"])
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
    return render_template("Customer/forgot_password.html")

@app.route("/reset_password", methods=["GET", "POST"])
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
    return render_template("Customer/reset_password.html")

##############################
#    REQUEST OTP ROUTE       #
##############################
@app.route("/request_otp", methods=["GET", "POST"])
@login_required
def request_otp():
    if current_user.account_type != "customer":
        app.logger.error("HTTP 403: Forbidden access to /request_otp by user %s (%s)",
                         current_user.username, current_user.account_type)
        if current_user.account_type == "super_admin":
            current_user.account_type = "admin"
            db.session.commit()
            flash("Forbidden: Only customers can request an OTP. Your account has been demoted to admin.", "danger")
            return redirect(url_for("admin_home", st=current_user.session_token))
        elif current_user.account_type == "employee":
            flash("Forbidden: Only customers can request an OTP.", "danger")
            return redirect(url_for("employee_home", st=current_user.session_token))
        else:
            flash("Forbidden: Only customers can request an OTP.", "danger")
            return redirect(url_for("login_page"))

    if request.method == "POST":
        data = request.get_json() or request.form
        email = data.get("email", "").strip()
        if not email:
            return jsonify({"success": False, "message": "Email is required."}), 400
        if email.lower() != current_user.email.lower():
            return jsonify({"success": False, "message": "Provided email does not match your account email."}), 403
        try:
            MFA.query.filter_by(user_id=current_user.user_id).delete()
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            app.logger.error("Error deleting existing OTPs for user %s: %s", current_user.user_id, e)
        otp = generate_secure_otp()
        expiration = datetime.now() + timedelta(minutes=10)
        new_mfa = MFA(user_id=current_user.user_id, code=otp, expiration=expiration)
        db.session.add(new_mfa)
        try:
            db.session.commit()
            send_verification_email(current_user.email, current_user.username, otp)
            return jsonify({"success": True, "message": "OTP sent to your email."}), 200
        except Exception as e:
            db.session.rollback()
            app.logger.error("Error sending OTP to user %s: %s", current_user.user_id, e)
            return jsonify({"success": False, "message": "Error sending OTP. Please try again later."}), 500

    return render_template("Customer/request_otp.html")

##############################
#    OTP VERIFY ROUTE        #
##############################
@app.route("/otp_verify", methods=["GET", "POST"])
@login_required
def otp_verify():
    if current_user.account_type != "customer":
        app.logger.error("HTTP 403: Forbidden access to /otp_verify by user %s (%s)",
                         current_user.username, current_user.account_type)
        if current_user.account_type == "super_admin":
            current_user.account_type = "admin"
            db.session.commit()
            flash("Forbidden: Only customers can verify OTP. Your account has been demoted to admin.", "danger")
            return redirect(url_for("admin_home", st=current_user.session_token))
        elif current_user.account_type == "employee":
            flash("Forbidden: Only customers can verify OTP.", "danger")
            return redirect(url_for("employee_home", st=current_user.session_token))
        else:
            flash("Forbidden: Only customers can verify OTP.", "danger")
            return redirect(url_for("login_page"))

    if request.method == "POST":
        data = request.get_json() or request.form
        otp = data.get("otp", "").strip()
        if not otp:
            return jsonify({"success": False, "message": "OTP is required."}), 400
        mfa_entry = MFA.query.filter_by(user_id=current_user.user_id, code=otp).first()
        if not mfa_entry or mfa_entry.expiration < datetime.now():
            return jsonify({"success": False, "message": "Invalid or expired OTP."}), 400
        try:
            db.session.delete(mfa_entry)
            db.session.commit()
            session["otp_verified"] = True
            return jsonify({"success": True, "message": "OTP verified."}), 200
        except Exception as e:
            db.session.rollback()
            app.logger.error("Error removing OTP for user %s: %s", current_user.user_id, e)
            return jsonify({"success": False, "message": "Database error while verifying OTP."}), 500

    return render_template("Customer/otp_verify.html")

##############################
#    ACCOUNT UPDATE ROUTE    #
##############################
@app.route("/account_update", methods=["GET", "POST"])
@login_required
def account_update():
    if current_user.account_type != "customer":
        app.logger.error("HTTP 403: Forbidden access to /account_update by user %s (%s)",
                         current_user.username, current_user.account_type)
        if current_user.account_type == "super_admin":
            current_user.account_type = "admin"
            db.session.commit()
            flash("Forbidden: This resource is only for customers. Your account has been demoted to admin.", "danger")
            return redirect(url_for("admin_home", st=current_user.session_token))
        elif current_user.account_type == "employee":
            flash("Forbidden: This resource is only for customers.", "danger")
            return redirect(url_for("employee_home", st=current_user.session_token))
        else:
            flash("Forbidden: This resource is only for customers.", "danger")
            return redirect(url_for("login_page"))

    if not session.get("otp_verified"):
        flash("You must verify your OTP before updating your account.", "warning")
        return redirect(url_for("otp_verify", st=current_user.session_token))

    if request.method == "POST":
        data = request.get_json() or request.form
        new_email = data.get("new_email", "").strip()
        new_password = data.get("new_password", "").strip()
        new_phone = data.get("new_phone", "").strip()
        if not new_email and not new_password and not new_phone:
            return jsonify({"success": True, "message": "No changes made. Redirecting to dashboard."}), 200
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
        except Exception as e:
            db.session.rollback()
            app.logger.error("Database error during account update for user %s: %s", current_user.user_id, e)
            return jsonify({"success": False, "message": "Database error."}), 500

    return render_template("Customer/account_update.html")

##############################
#       REVIEWS ENDPOINT     #
##############################
@app.route("/api/reviews", methods=["GET", "POST"])
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
        except Exception:
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
    data_list = [{
            "rating_header": r.rating_header,
            "rating_notes": r.rating_notes,
            "rating_value": r.rating_value,
            "created_at": r.created_at.strftime("%Y-%m-%d %H:%M:%S")
        } for r in my_reviews]
    return jsonify({"success": True, "reviews": data_list}), 200

##############################
#       EMERGENCY ENDPOINT   #
##############################
@app.route("/api/emergency", methods=["GET", "POST"])
@login_required
def api_emergency():
    if current_user.account_type != "customer":
        return jsonify({"success": False, "message": "Unauthorized."}), 403

    if request.method == "POST":
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"success": False, "message": "Invalid JSON payload."}), 400

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

    else:
        my_ems = Emergencies.query.filter_by(user_id=current_user.user_id).all()
        data_list = [{
            "emergency_id": em.emergency_id,
            "location_details": em.location_details,
            "distress_notes": em.distress_notes,
            "assigned_employee_id": em.assigned_employee_id,
            "created_at": em.created_at.strftime("%Y-%m-%d %H:%M:%S")
        } for em in my_ems]
        return jsonify({"success": True, "emergencies": data_list}), 200

##############################
#   CHAT MESSAGES ENDPOINT   #
##############################
@app.route("/api/chat/messages", methods=["GET", "POST"])
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
    data_list = [{
            "username": (Users.query.get(m.user_id).username if Users.query.get(m.user_id) else "Unknown"),
            "message": m.message,
            "timestamp": m.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        } for m in msgs]
    return jsonify({"success": True, "messages": data_list}), 200

##############################
#   ADMIN: CREATE EMPLOYEE   #
##############################
@app.route("/api/admin/create_employee", methods=["POST"])
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
@login_required
def admin_assign_emergency():
    if current_user.account_type not in ["admin", "super_admin"]:
        return jsonify({"success": False, "message": "Unauthorized. Admins only."}), 403
    data = request.get_json()
    emergency_id = data.get("emergency_id")
    employee_id = data.get("employee_id")
    if not emergency_id or not employee_id:
        return jsonify({"success": False, "message": "emergency_id and employee_id required"}), 400
    emergency = Emergencies.query.get(emergency_id)
    if not emergency:
        return jsonify({"success": False, "message": "Emergency not found."}), 404
    employee_user = Users.query.get(employee_id)
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
        customer_user = Users.query.get(emergency.user_id)
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
@login_required
def admin_unassign_emergency():
    if current_user.account_type not in ["admin", "super_admin"]:
        return jsonify({"success": False, "message": "Unauthorized. Admins only."}), 403
    data = request.get_json()
    emergency_id = data.get("emergency_id")
    if not emergency_id:
        return jsonify({"success": False, "message": "emergency_id required"}), 400
    emergency = Emergencies.query.get(emergency_id)
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
        employee_user = Users.query.get(current_assignee)
        customer_user = Users.query.get(emergency.user_id)
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
@login_required
def admin_delete_employee():
    if current_user.account_type not in ["admin", "super_admin"]:
        return jsonify({"success": False, "message": "Unauthorized. Admins only."}), 403
    data = request.get_json()
    employee_id = data.get("employee_id")
    if not employee_id:
        return jsonify({"success": False, "message": "employee_id required"}), 400
    user_to_delete = Users.query.get(employee_id)
    if not user_to_delete or user_to_delete.account_type not in ["employee", "admin"]:
        return jsonify({"success": False, "message": "User is not an employee/admin or does not exist."}), 400
    if user_to_delete.is_locked:
        return jsonify({"success": False, "message": "Cannot delete a locked account. Unlock first."}), 403
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
            except Exception:
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
@login_required
def admin_update_staff(staff_id):
    if current_user.account_type not in ["admin", "super_admin"]:
        return jsonify({"success": False, "message": "Unauthorized. Admins only."}), 403
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    phone_number = data.get("phone_number")
    is_locked = data.get("is_locked")
    user = Users.query.get(staff_id)
    if not user or user.account_type not in ["employee", "admin"]:
        return jsonify({"success": False, "message": "User not found or not an employee/admin."}), 404
    if user.is_locked:
        if current_user.account_type == "super_admin" and is_locked is False:
            user.is_locked = False
            db.session.commit()
            return jsonify({"success": True, "message": "Locked account unlocked by super_admin."}), 200
        else:
            return jsonify({"success": False, "message": "Cannot update locked account (unless super_admin unlocking)."}), 403
    if user.account_type == "super_admin" and user.user_id == current_user.user_id:
        return jsonify({"success": False, "message": "Super Admin cannot modify their own account."}), 403
    if username:
        user.username = username
    if email:
        existing = Users.query.filter(Users.email == email, Users.user_id != staff_id).first()
        if existing:
            return jsonify({"success": False, "message": "Email already in use."}), 400
        user.email = email
    if password:
        user.password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
    if phone_number:
        user.phone_number = phone_number
    if is_locked is not None and current_user.account_type == "super_admin":
        if user.account_type == "super_admin":
            return jsonify({"success": False, "message": "Cannot lock/unlock another Super Admin."}), 403
        if is_locked is True:
            user.is_locked = True
            user.session_token = None
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
            except Exception:
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
    return render_template("Admin/admin_setup.html")

##############################
#   SUPER ADMIN ROUTES       #
##############################
@app.route("/api/elevate_super_admin", methods=["POST"])
@login_required
def elevate_super_admin_route():
    if current_user.account_type != "admin":
        return jsonify({"success": False, "message": "Unauthorized. Admins only."}), 403
    attempts = session.get("elevate_super_admin_attempts", 0)
    if attempts >= 3:
        return jsonify({"success": False, "message": "Max attempts reached. Contact existing super admin."}), 403
    existing_super_admin = Users.query.filter_by(account_type="super_admin").first()
    if existing_super_admin:
        return jsonify({"success": False, "message": "A super admin already exists."}), 403
    data = request.get_json()
    root_password = data.get("root_password", "").strip()
    expected_root_password = os.getenv("ROOT_PASSWORD", "")
    if root_password == expected_root_password:
        try:
            current_user.account_type = "super_admin"
            db.session.commit()
            login_user(current_user)
            app.logger.info(f"User {current_user.username} elevated to super_admin.")
            return jsonify({"success": True, "message": "Elevated to super admin."}), 200
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Database error during elevation: {e}")
            return jsonify({"success": False, "message": f"Database error: {e}"}), 500
    else:
        attempts += 1
        session["elevate_super_admin_attempts"] = attempts
        if attempts >= 3:
            return jsonify({"success": False, "message": "Max attempts reached."}), 403
        else:
            return jsonify({"success": False, "message": "Incorrect root password."}), 401

@app.route("/api/admin/lock_account", methods=["POST"])
@login_required
def admin_lock_account():
    if current_user.account_type not in ["admin", "super_admin"]:
        return jsonify({"success": False, "message": "Unauthorized. Admins only."}), 403
    data = request.get_json()
    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"success": False, "message": "user_id is required."}), 400
    user = Users.query.get(user_id)
    if not user or user.account_type not in ["employee", "admin"]:
        return jsonify({"success": False, "message": "User not found or not an employee/admin."}), 404
    if user.account_type == "super_admin" and user.user_id == current_user.user_id:
        return jsonify({"success": False, "message": "Super Admin cannot lock their own account."}), 403
    if user.is_locked:
        return jsonify({"success": False, "message": "Account is already locked."}), 400
    user.is_locked = True
    user.session_token = None
    try:
        assigned_emergencies = Emergencies.query.filter_by(assigned_employee_id=user.user_id).all()
        for em in assigned_emergencies:
            em.assigned_employee_id = None
            customer_obj = Users.query.get(em.user_id)
            if customer_obj:
                send_assignment_email_to_customer(
                    customer=customer_obj,
                    emergency_id=em.emergency_id,
                    location_details=em.location_details,
                    distress_notes=em.distress_notes if em.distress_notes else "",
                    assigned=False
                )
        db.session.commit()
        send_employee_locked_email(user)
        return jsonify({
            "success": True,
            "message": ("Account locked successfully. All assigned emergencies have been unassigned and notifications sent.")
        }), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Database error during account lock: {str(e)}")
        return jsonify({"success": False, "message": "Server error. Please try again later."}), 500

@app.route("/api/admin/unlock_account", methods=["POST"])
@login_required
def admin_unlock_account():
    if current_user.account_type not in ["admin", "super_admin"]:
        return jsonify({"success": False, "message": "Unauthorized. Admins only."}), 403
    data = request.get_json()
    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"success": False, "message": "user_id is required."}), 400
    user = Users.query.get(user_id)
    if not user or user.account_type not in ["employee", "admin"]:
        return jsonify({"success": False, "message": "User not found or not an employee/admin."}), 404
    if not user.is_locked:
        return jsonify({"success": False, "message": "Account is not locked."}), 400
    user.is_locked = False
    try:
        db.session.commit()
        try:
            html_content = render_template("emails/account_unlocked.html", user=user, current_year=datetime.utcnow().year)
            send_email(to=user.email, subject="Your Account Has Been Unlocked", body=html_content, html=True)
            app.logger.info(f"Unlock email sent to {user.username} ({user.email}).")
        except Exception as e:
            app.logger.error(f"Failed to send unlock email to {user.username}: {e}")
        return jsonify({"success": True, "message": "Account unlocked successfully."}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Database error during account unlock: {str(e)}")
        return jsonify({"success": False, "message": "Server error. Please try again later."}), 500

##############################
#   Helper Functions         #
##############################
def send_verification_email(to_email, username, verification_code):
    subject = "Cave Country Canoes Account Verification Code"
    body = f"""Dear {username},

Your verification code is {verification_code}.

- Cave Country Canoes"""
    send_email(to_email, subject, body, html=False)

def send_assignment_email_to_employee(employee, customer, emergency_id=None, location_details=None, distress_notes=None, admin_user=None, assigned=True):
    if assigned:
        if admin_user:
            subject = "New Emergency Assignment"
            app.logger.debug(f"Sending assignment email to employee {employee.username} with distress_notes: {distress_notes}")
            body = f"""Dear {employee.username},

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

- Cave Country Canoes"""
            send_email(employee.email, subject, body, html=False)
        else:
            subject = "New Emergency Assignment Notification"
            app.logger.debug(f"Sending assignment email to employee {employee.username} with customer details.")
            html_content = render_template("emails/employee_contact_details.html",
                                           employee=employee,
                                           customer=customer,
                                           emergency_id=emergency_id,
                                           location_details=location_details,
                                           distress_notes=distress_notes,
                                           current_year=datetime.utcnow().year)
            send_email(employee.email, subject, html_content, html=True)
    else:
        subject = "Emergency Tracking Termination Notification"
        app.logger.debug(f"Sending termination email to employee {employee.username} for emergency ID {emergency_id}.")
        body = f"""Dear {employee.username},

Your assignment to track Emergency Log ID {emergency_id if emergency_id else 'N/A'} has been terminated by an admin.

- Cave Country Canoes"""
        send_email(employee.email, subject, body, html=False)

def send_assignment_email_to_customer(customer, emergency_id=None, location_details=None, distress_notes=None, employee_username=None, employee_phone=None, employee_email=None, assigned=True):
    if assigned:
        subject = "Emergency Tracking Assignment"
        app.logger.debug(f"Sending assignment email to customer {customer.username} with distress_notes: {distress_notes}")
        html_content = render_template("emails/customer_assignment_email.html",
                                       customer=customer,
                                       emergency_id=emergency_id,
                                       location_details=location_details,
                                       distress_notes=distress_notes,
                                       employee_username=employee_username,
                                       employee_phone=employee_phone,
                                       employee_email=employee_email)
        send_email(customer.email, subject, html_content, html=True)
    else:
        subject = "Emergency Tracking Termination Notice"
        app.logger.debug(f"Sending termination email to customer {customer.username} with distress_notes: {distress_notes}")
        body = f"""Dear {customer.username},

Your assigned employee has been unassigned by an admin.
If you have any questions, please reach out via chat.

- Cave Country Canoes"""
        send_email(customer.email, subject, body, html=False)

def send_employee_locked_email(employee):
    subject = "Your Account Has Been Locked"
    current_year = datetime.now().year
    html_content = render_template("emails/employee_locked.html", employee=employee, current_year=current_year)
    send_email(to=employee.email, subject=subject, body=html_content, html=True)

def send_email(to, subject, body, html=False):
    msg = EmailMessage()
    msg["From"] = app.config['MAIL_DEFAULT_SENDER']
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    if html:
        msg.add_alternative(body, subtype='html')
    context = ssl.create_default_context()
    try:
        with smtplib.SMTP_SSL(app.config['MAIL_SERVER'], app.config['MAIL_PORT'], context=context) as smtp:
            smtp.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
            smtp.send_message(msg)
        app.logger.info(f"Email sent to {to} with subject '{subject}'.")
    except Exception as e:
        app.logger.error(f"Failed to send email to {to}: {e}")
        app.logger.error(traceback.format_exc())

##############################
#  SESSION VALIDATION        #
##############################
def validate_session_token():
    if current_user.is_authenticated:
        param_token = request.args.get('st')
        if not param_token or param_token != current_user.session_token:
            logout_user()
            session.clear()
            flash("Your session token is invalid or missing. Please log in again.", "warning")
            return redirect(url_for("login_page"))

##############################
#   EMPLOYEE DASHBOARD ROUTES #
##############################
@app.route("/employee/home")
@login_required
def employee_home():
    if current_user.account_type != "employee":
        flash("Unauthorized access. Redirecting to login.", "warning")
        return redirect(url_for("login_page"))
    return render_template("Employee/employee_home.html", username=current_user.username)

@app.route("/employee/see_all_emergencies")
@login_required
def see_all_emergencies():
    if current_user.account_type != "employee":
        flash("Unauthorized access. Redirecting to login.", "warning")
        return redirect(url_for("login_page"))
    all_emergencies = Emergencies.query.all()
    data = [{
            "emergency_id": emergency.emergency_id,
            "location_details": emergency.location_details,
            "distress_notes": emergency.distress_notes,
            "is_claimed": emergency.assigned_employee_id is not None,
            "claimed_by": emergency.assigned_employee.username if emergency.assigned_employee_id else None,
        } for emergency in all_emergencies]
    return render_template("Employee/see_all_emergencies.html", emergencies=data)

@app.route("/employee/claim_emergency", methods=["POST"])
@login_required
def claim_emergency():
    app.logger.debug(f"User attempting claim: id={current_user.user_id}, account_type={current_user.account_type}")
    if current_user.account_type != "employee":
        app.logger.warning(f"Unauthorized access attempt by user {current_user.username} with type {current_user.account_type}.")
        return jsonify({"success": False, "message": "Unauthorized"}), 403
    try:
        data = request.get_json()
        app.logger.debug(f"Received claim data: {data}")
        emergency_id = data.get("emergency_id")
        if not emergency_id:
            app.logger.error("Missing emergency ID in request.")
            return jsonify({"success": False, "message": "Emergency ID is required."}), 400

        emergency = Emergencies.query.get(emergency_id)
        if not emergency:
            app.logger.error(f"Emergency ID {emergency_id} not found.")
            return jsonify({"success": False, "message": "Emergency not found."}), 404
        if emergency.assigned_employee_id:
            app.logger.info(f"Emergency ID {emergency_id} already claimed by user ID {emergency.assigned_employee_id}.")
            return jsonify({"success": False, "message": "Emergency already claimed."}), 400

        emergency.assigned_employee_id = current_user.user_id
        db.session.commit()

        customer = Users.query.get(emergency.user_id)
        if not customer:
            app.logger.error(f"Customer with ID {emergency.user_id} not found.")
            return jsonify({"success": False, "message": "Associated customer not found."}), 404

        send_assignment_email_to_customer(
            customer=customer,
            emergency_id=emergency.emergency_id,
            location_details=emergency.location_details,
            distress_notes=emergency.distress_notes,
            employee_username=current_user.username,
            employee_phone=current_user.phone_number,
            employee_email=current_user.email,
            assigned=True
        )
        send_assignment_email_to_employee(
            employee=current_user,
            customer=customer,
            emergency_id=emergency.emergency_id,
            location_details=emergency.location_details,
            distress_notes=emergency.distress_notes,
            assigned=True
        )
        app.logger.info(f"Emergency ID {emergency_id} claimed successfully by {current_user.username}.")
        return jsonify({"success": True, "message": "Emergency claimed successfully."}), 200

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error claiming emergency: {str(e)}")
        return jsonify({"success": False, "message": f"An error occurred: {str(e)}"}), 500

@app.route("/employee/resolve_emergency", methods=["POST"])
@login_required
def resolve_emergency():
    if current_user.account_type != "employee":
        app.logger.warning(f"Unauthorized access attempt by user {current_user.username}.")
        return jsonify({"success": False, "message": "Unauthorized access."}), 403
    try:
        data = request.get_json()
        emergency_id = data.get("emergency_id")
        if not emergency_id:
            app.logger.error("Missing emergency ID in request.")
            return jsonify({"success": False, "message": "Emergency ID is required."}), 400
        emergency = db.session.get(Emergencies, emergency_id)
        if not emergency:
            app.logger.error(f"Emergency ID {emergency_id} not found.")
            return jsonify({"success": False, "message": "Emergency not found."}), 404
        if emergency.assigned_employee_id != current_user.user_id:
            app.logger.warning(f"User {current_user.username} is not assigned to emergency {emergency_id}.")
            return jsonify({"success": False, "message": "You are not assigned to this emergency."}), 403
        db.session.delete(emergency)
        db.session.commit()
        app.logger.info(f"Emergency ID {emergency_id} resolved by user {current_user.username}.")
        return jsonify({"success": True, "message": "Emergency resolved successfully."}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error while resolving emergency: {str(e)}")
        return jsonify({"success": False, "message": f"An error occurred: {str(e)}"}), 500

@app.route("/employee/see_claimed_emergencies", methods=["GET", "POST"])
@login_required
def see_claimed_emergencies():
    if current_user.account_type != "employee":
        flash("Unauthorized access. Redirecting to login.", "warning")
        return redirect(url_for("login_page"))
    if request.method == "POST":
        try:
            data = request.get_json()
            emergency_id = data.get("emergency_id")
            if not emergency_id:
                app.logger.error("Missing emergency ID in request.")
                return jsonify({"success": False, "message": "Emergency ID is required."}), 400
            emergency = db.session.get(Emergencies, emergency_id)
            if not emergency or emergency.assigned_employee_id != current_user.user_id:
                app.logger.warning(f"Emergency ID {emergency_id} not found or not assigned to user {current_user.username}.")
                return jsonify({"success": False, "message": "Emergency not found or not assigned to you."}), 404
            db.session.delete(emergency)
            db.session.commit()
            app.logger.info(f"Emergency ID {emergency_id} resolved and removed by user {current_user.username}.")
            return jsonify({"success": True, "message": "Emergency resolved and removed successfully."}), 200
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error resolving emergency: {str(e)}")
            return jsonify({"success": False, "message": f"Error: {e}"}), 500
    emergencies = Emergencies.query.filter_by(assigned_employee_id=current_user.user_id).all()
    data = [{
            "emergency_id": em.emergency_id,
            "location_details": em.location_details,
            "distress_notes": em.distress_notes,
            "customer": em.customer.username if em.customer else "Unknown",
        } for em in emergencies]
    return render_template("Employee/see_claimed_emergencies.html", emergencies=data)

@app.route("/employee/see_all_reviews")
@login_required
def see_all_reviews():
    if current_user.account_type != "employee":
        flash("Unauthorized access. Redirecting to login.", "warning")
        return redirect(url_for("login_page"))
    reviews = Ratings.query.all()
    data = [{
            "username": review.user.username if review.user else "Anonymous",
            "rating_header": review.rating_header,
            "rating_notes": review.rating_notes,
            "rating_value": review.rating_value,
        } for review in reviews]
    return render_template("Employee/see_all_reviews.html", reviews=data)

@app.route("/employee/chat")
@login_required
def employee_chat():
    if current_user.account_type != "employee":
        flash("Unauthorized access. Redirecting to login.", "warning")
        return redirect(url_for("login_page"))
    return render_template("Employee/employee_chat.html", username=current_user.username)

@app.route("/employee/logout", methods=["GET", "POST"])
@login_required
def employee_logout():
    logout_user()
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for("login_page"))

##############################
#   EMAIL TEMPLATE ROUTES    #
##############################
@app.route("/emails/employee_locked.html")
def employee_locked_email():
    return render_template("emails/employee_locked.html")

@app.route("/emails/account_unlocked.html")
def account_unlocked_email():
    return render_template("emails/account_unlocked.html")

##############################
#       MAIN RUN             #
##############################
if __name__ == "__main__":
    ip = get_local_ip()
    app.run(host=ip, debug=False, threaded=False)