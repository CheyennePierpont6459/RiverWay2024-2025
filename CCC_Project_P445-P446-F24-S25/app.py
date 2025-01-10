import hashlib
import os
import secrets
import smtplib
import socket
import ssl
from datetime import datetime, timedelta
from email.message import EmailMessage

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

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

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
    DB_PASSWORD = quote_plus(os.getenv("DB_PASSWORD", "<put your db password here>"))
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

# Mail config
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')  # Replace with your SMTP server
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 465))  # Typically 465 for SMTP_SSL
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL', 'True') == 'True'  # Use SSL instead of TLS
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
mail = Mail(app)

# Rate Limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)
limiter.init_app(app)


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
    return db.session.get(Users, int(user_id))


class Users(db.Model, UserMixin):
    __tablename__ = "users"
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    account_type = db.Column(db.String(20), nullable=False, default="customer")
    created_at = db.Column(db.DateTime, default=datetime.now())

    @property
    def id(self):
        return self.user_id


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


class MFA(db.Model):
    __tablename__ = "mfa"
    mfa_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    code = db.Column(db.String(6), nullable=False)
    expiration = db.Column(db.DateTime, nullable=False)


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


#########################
#       ROUTES          #
#########################

@app.route("/")
def index():
    return redirect(url_for("login_page"))


@app.route("/login_page")
def login_page():
    if current_user.is_authenticated:
        if current_user.account_type == "admin":
            return redirect(url_for("admin_home"))
        elif current_user.account_type == "customer":
            return redirect(url_for("customer_dashboard"))
        elif current_user.account_type == "employee":
            return redirect(url_for("employee_dashboard"))
    return render_template("login.html")


@app.route("/signup_page")
def signup_page():
    if current_user.is_authenticated:
        if current_user.account_type == "admin":
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
    elif current_user.account_type == "admin":
        return redirect(url_for("admin_home"))
    else:
        # Employee
        return redirect(url_for("employee_dashboard"))


@app.route("/employee_dashboard")
@login_required
def employee_dashboard():
    """
    A minimal Employee Dashboard so employees can see their assigned emergencies.
    """
    if current_user.account_type != "employee":
        if current_user.account_type == "admin":
            return redirect(url_for("admin_home"))
        elif current_user.account_type == "customer":
            return redirect(url_for("customer_dashboard"))
        else:
            return redirect(url_for("login_page"))
    # Fetch all emergencies assigned to the current employee
    assigned_emergencies = Emergencies.query.filter(
        Emergencies.distress_notes.like(f"%[ASSIGNED_EMPLOYEE={current_user.user_id}]%")
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
        if current_user.account_type == "admin":
            return redirect(url_for("admin_home"))
        else:
            return redirect(url_for("employee_dashboard"))
    return render_template("customer_reviews.html")


@app.route("/submit_log_page")
@login_required
def submit_log_page():
    if current_user.account_type != "customer":
        if current_user.account_type == "admin":
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
    if current_user.account_type != "admin":
        if current_user.account_type == "employee":
            return redirect(url_for("employee_dashboard"))
        return redirect(url_for("customer_dashboard"))

    total_customers = Users.query.filter_by(account_type="customer").count()
    total_employees = Users.query.filter_by(account_type="employee").count()
    total_emergencies = Emergencies.query.count()
    unresolved_emergencies = Emergencies.query.filter(
        ~Emergencies.distress_notes.like("%[ASSIGNED_EMPLOYEE=%")
    ).count()

    stats = {
        "total_customers": total_customers,
        "total_employees": total_employees,
        "total_emergencies": total_emergencies,
        "unresolved_emergencies": unresolved_emergencies
    }

    return render_template("admin_home.html", stats=stats)


@app.route("/admin/manage_employees")
@login_required
def admin_manage_employees():
    if current_user.account_type != "admin":
        if current_user.account_type == "employee":
            return redirect(url_for("employee_dashboard"))
        return redirect(url_for("customer_dashboard"))

    employees = Users.query.filter_by(account_type="employee").all()
    return render_template("admin_manage_employees.html", employees=employees)


@app.route("/admin/manage_emergencies")
@login_required
def admin_manage_emergencies():
    if current_user.account_type != "admin":
        if current_user.account_type == "employee":
            return redirect(url_for("employee_dashboard"))
        return redirect(url_for("customer_dashboard"))

    all_ems = Emergencies.query.all()
    employees = Users.query.filter_by(account_type="employee").all()

    data_emergencies = []
    for em in all_ems:
        assigned_id = parse_assigned_employee_id(em.distress_notes)
        assigned_user = None
        if assigned_id:
            assigned_user = db.session.get(Users, assigned_id)
        customer_obj = db.session.get(Users, em.user_id)
        customer_name = customer_obj.username if customer_obj else "Unknown"
        customer_phone = customer_obj.phone_number if customer_obj else "N/A"

        data_emergencies.append({
            "emergency_id": em.emergency_id,
            "location_details": em.location_details,
            "distress_notes": em.distress_notes,
            "assigned_employee_id": assigned_id,
            "assigned_employee_name": assigned_user.username if assigned_user else None,
            "customer_name": customer_name,
            "customer_phone": customer_phone
        })

    return render_template("admin_manage_emergencies.html",
                           emergencies=data_emergencies,
                           employees=employees)


@app.route("/admin/chat")
@login_required
def admin_chat():
    if current_user.account_type != "admin":
        if current_user.account_type == "employee":
            return redirect(url_for("employee_dashboard"))
        return redirect(url_for("customer_dashboard"))
    return render_template("admin_chat.html", username=current_user.username, account_type=current_user.account_type)


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

    user_exists = Users.query.filter_by(username=username).first()
    if user_exists:
        return jsonify({"success": False, "message": "Username already exists!"}), 400
    email_exists = Users.query.filter_by(email=email).first()
    if email_exists:
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
@limiter.limit("10 per minute")
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


@app.route("/api/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    session.clear()
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
        expiration = datetime.utcnow() + timedelta(minutes=10)
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
        if not mfa_entry or mfa_entry.expiration < datetime.utcnow():
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
#   OTP + ACCOUNT UPDATE     #
##############################

@app.route("/request_otp_page", methods=["GET", "POST"])
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
            return jsonify({"success": True, "message": "Verification code sent to email."}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "message": f"Failed: {e}"}), 500

    return render_template("request_otp_page.html")


@app.route("/otp_verify", methods=["GET", "POST"])
@login_required
def otp_verify():
    if request.method == "POST":
        data = request.get_json()
        otp = data.get("otp")

        if not otp:
            return jsonify({"success": False, "message": "OTP is required."}), 400

        mfa_entry = MFA.query.filter_by(user_id=current_user.user_id, code=otp).first()
        if not mfa_entry or mfa_entry.expiration < datetime.utcnow():
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
@login_required
@limiter.limit("20 per hour")
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
@login_required
@limiter.limit("30 per hour")
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
        assigned_id = parse_assigned_employee_id(em.distress_notes)
        data_list.append({
            "emergency_id": em.emergency_id,
            "location_details": em.location_details,
            "distress_notes": em.distress_notes,
            "assigned_employee_id": assigned_id,
            "created_at": em.created_at.strftime("%Y-%m-%d %H:%M:%S")
        })
    return jsonify({"success": True, "emergencies": data_list}), 200


##############################
#   CHAT MESSAGES ENDPOINT   #
##############################

@app.route("/api/chat/messages", methods=["GET", "POST"])
@login_required
@limiter.limit("100 per hour")
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
@login_required
@limiter.limit("5 per minute")
def admin_create_employee():
    if current_user.account_type != "admin":
        return jsonify({"success": False, "message": "Unauthorized. Admin only."}), 403

    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    phone_number = data.get("phone_number")

    if not username or not email or not password or not phone_number:
        return jsonify({"success": False, "message": "All fields are required."}), 400

    existing_user = Users.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({"success": False, "message": "Username already exists."}), 400
    existing_email = Users.query.filter_by(email=email).first()
    if existing_email:
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
#   ADMIN: ASSIGN/UNASSIGN   #
##############################

@app.route("/api/admin/assign_emergency", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def admin_assign_emergency():
    if current_user.account_type != "admin":
        return jsonify({"success": False, "message": "Unauthorized. Admin only."}), 403

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

    existing_emp_id = parse_assigned_employee_id(emergency.distress_notes)
    if existing_emp_id is not None:
        return jsonify({"success": False, "message": "Already assigned."}), 400

    updated = update_assigned_employee_id(emergency.distress_notes, new_employee_id=employee_id)
    emergency.distress_notes = updated

    try:
        db.session.commit()

        customer_user = db.session.get(Users, emergency.user_id)

        # Send assignment emails
        send_assignment_email_to_employee(
            employee=employee_user,
            customer=customer_user,
            emergency_id=emergency.emergency_id,
            location_details=emergency.location_details,
            distress_notes=emergency.distress_notes,
            admin_user=current_user,
            assigned=True
        )
        send_assignment_email_to_customer(
            customer=customer_user,
            emergency_id=emergency.emergency_id,
            location_details=emergency.location_details,
            distress_notes=emergency.distress_notes,
            employee_username=employee_user.username,
            employee_phone=employee_user.phone_number,
            employee_email=employee_user.email,
            assigned=True
        )

        return jsonify({"success": True, "message": "Assigned successfully."}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": f"DB error: {e}"}), 500


@app.route("/api/admin/unassign_emergency", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def admin_unassign_emergency():
    if current_user.account_type != "admin":
        return jsonify({"success": False, "message": "Unauthorized. Admin only."}), 403

    data = request.get_json()
    emergency_id = data.get("emergency_id")
    if not emergency_id:
        return jsonify({"success": False, "message": "emergency_id required"}), 400

    emergency = Emergencies.query.get(emergency_id)
    if not emergency:
        return jsonify({"success": False, "message": "Emergency not found."}), 404

    current_assignee = parse_assigned_employee_id(emergency.distress_notes)
    if current_assignee is None:
        return jsonify({"success": False, "message": "No assigned employee."}), 400

    updated = update_assigned_employee_id(emergency.distress_notes, new_employee_id=None)
    emergency.distress_notes = updated
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
                distress_notes=emergency.distress_notes,
                admin_user=current_user,
                assigned=False
            )
        send_assignment_email_to_customer(
            customer=customer_user,
            emergency_id=emergency.emergency_id,
            location_details=emergency.location_details,
            distress_notes=emergency.distress_notes,
            assigned=False
        )

        return jsonify({"success": True, "message": "Unassigned successfully."}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": f"DB error: {e}"}), 500


##############################
#  ADMIN: DELETE EMPLOYEE    #
##############################

@app.route("/api/admin/delete_employee", methods=["POST"])
@login_required
@limiter.limit("5 per minute")
def admin_delete_employee():
    if current_user.account_type != "admin":
        return jsonify({"success": False, "message": "Unauthorized. Admin only."}), 403

    data = request.get_json()
    employee_id = data.get("employee_id")
    if not employee_id:
        return jsonify({"success": False, "message": "employee_id required"}), 400

    user_to_delete = Users.query.get(employee_id)
    if not user_to_delete or user_to_delete.account_type != "employee":
        return jsonify({"success": False, "message": "User is not an employee or does not exist."}), 400

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

        return jsonify({"success": True, "message": f"Employee (ID={employee_id}) removed."}), 200
    except Exception as e:
        app.logger.error(f"Delete Employee Error: {e}")
        return jsonify({"success": False, "message": f"Database error: {e}"}), 500


##############################
#       DELETE ACCOUNT       #
##############################

@app.route("/api/delete_account", methods=["POST"])
@login_required
@limiter.limit("2 per hour")
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
@limiter.limit("1 per day")
def admin_setup():
    """
    This route allows the creation of the first admin account.
    If an admin already exists, it flashes a message with admin email(s) and redirects to login.
    Otherwise, it allows creating a new admin account by verifying the root password.
    """
    existing_admin = Users.query.filter_by(account_type="admin").first()
    if existing_admin:
        # Admin exists, retrieve all admin emails
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

        expected_root_password = os.getenv("ADMIN_SETUP_PASSWORD", "")
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


#########################
#   EMAIL FUNCTIONS     #
#########################

def send_verification_email(to_email, username, verification_code):
    subject = "Cave Country Canoes Account Verification Code"
    body = f"""
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
        body = f"""
        Dear {employee.username},

        You have been assigned to track the following customer's emergency.

        Emergency Details:
        - Emergency Log ID: {emergency_id if emergency_id else 'N/A'}
        - Location Details: {location_details if location_details else 'N/A'}
        - Distress Notes: {distress_notes if distress_notes else 'N/A'}

        Customer Details:
        - Name: {customer.username}
        - Phone: {customer.phone_number}
        - Email: {customer.email}

        Assigned by Admin:
        - Username: {admin_user.username if admin_user else 'N/A'}
        - Phone: {admin_user.phone_number if admin_user else 'N/A'}
        - Email: {admin_user.email if admin_user else 'N/A'}

        - Cave Country Canoes
        """
    else:
        subject = "Emergency Log Termination Notice"
        body = f"""
        Dear {employee.username},

        An admin ({admin_user.username if admin_user else 'N/A'}) has terminated your tracking of:

        Emergency Details:
        - Emergency Log ID: {emergency_id if emergency_id else 'N/A'}
        - Location Details: {location_details if location_details else 'N/A'}
        - Distress Notes: {distress_notes if distress_notes else 'N/A'}

        Customer Details:
        - Name: {customer.username}
        - Phone: {customer.phone_number}
        - Email: {customer.email}

        - Cave Country Canoes
        """
    send_email(employee.email, subject, body, html=True)


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
        body = f"""
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
        body = f"""
        Dear {customer.username},

        Your assigned employee has been unassigned by an admin.
        If you have any questions, please reach out via chat.

        - Cave Country Canoes
        """
    send_email(customer.email, subject, body, html=True)


def send_email(to_address, subject, body, html=False):
    email_sender = os.getenv("MAIL_USERNAME")
    email_password = os.getenv("MAIL_PASSWORD")
    em = EmailMessage()
    em["From"] = email_sender
    em["To"] = to_address
    em["Subject"] = subject
    if html:
        em.add_alternative(body, subtype='html')
    else:
        em.set_content(body)

    context = ssl.create_default_context()
    try:
        with smtplib.SMTP_SSL(os.getenv("MAIL_SERVER", "smtp.gmail.com"),
                              int(os.getenv("MAIL_PORT", 465)), context=context) as smtp:
            smtp.login(email_sender, email_password)
            smtp.sendmail(email_sender, to_address, em.as_string())
        app.logger.info(f"Email sent to {to_address} with subject '{subject}'.")
    except Exception as e:
        app.logger.error(f"Failed to send email to {to_address}: {e}")


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
#       RUN SERVER      #
#########################

if __name__ == "__main__":
    local_ip = get_local_ip()
    print(f"Running on http://{local_ip}:6731")
    app.run(host=local_ip, port=6731, debug=True)