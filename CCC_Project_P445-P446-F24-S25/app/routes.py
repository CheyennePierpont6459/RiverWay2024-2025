"""
All application routes for the CCC Emergency Map.

This module defines the Flask blueprint 'main' containing all routes,
helper functions for input sanitization (using Bleach), email logic, and session handling.
It supports:
  - Account signup with email verification via an HTML email link.
  - Sending six-character OTPs for sensitive actions.
  - Standard login/logout and dashboard routes.
"""

import hashlib
import socket
import secrets
import smtplib
import traceback
import re
from datetime import datetime, timedelta
from email.message import EmailMessage
from html import unescape  # For relaxing our flagger

from flask import (
    Blueprint, render_template, redirect, url_for,
    request, jsonify, session, flash, current_app
)
from flask_login import login_user, current_user, logout_user, login_required
from sqlalchemy import text
from .utils import send_email, send_verification_email
# Import .extensions and models
from .extensions import db, bcrypt, login_manager
from .models import (
    Users, PendingUser, Ratings,
    Emergencies, ChatMessages, MFA
)
import bleach

###########################
#  Input Sanitization
###########################
def sanitize_input(context):
    """Sanitizes input by stripping all HTML tags using Bleach.
    (Passwords are not sanitized here to allow special characters.)
    """
    if context is None:
        return None
    return bleach.clean(context, tags=[], strip=True)

def is_modified(raw, sanitized):
    """Return True if the raw input was modified by sanitization."""
    return raw != unescape(sanitized)

def is_allowed_input(raw, sanitized):
    """
    Returns True if the raw input is allowed.
    Allow if raw equals the unescaped sanitized value, or if it matches a whitelist of emoticons.
    Disallow mirrored tag patterns; otherwise, reject.
    """
    if raw == unescape(sanitized):
        return True
    allowed_patterns = [
        r"^<3$",       # heart
        r"^:-\)$",     # smiley with nose
        r"^:\)$",      # simple smiley
        r"^:\D$",      # big smiley
        r"^;\)$",      # wink
    ]
    for pattern in allowed_patterns:
        if re.fullmatch(pattern, raw):
            return True
    if re.search(r"<\s*(\w+)\s*>\s*<\\\s*\1\s*>", raw, re.IGNORECASE):
        return False
    return False

###########################
# Helper Functions
###########################
def generate_secure_otp():
    random_bytes = secrets.token_bytes(16)
    return hashlib.sha256(random_bytes).hexdigest()[:6].upper()

def get_local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"

def generate_unique_session_token():
    while True:
        token = secrets.token_hex(32)
        if not Users.query.filter_by(session_token=token).first():
            return token

def remove_assigned_employee_marker(distress_text):
    """
    Remove any "[ASSIGNED_EMPLOYEE=...]" marker from the distress_text.
    """
    if not distress_text:
        return ""
    start = distress_text.find("[ASSIGNED_EMPLOYEE=")
    if start != -1:
        # Return text only before the marker (strip trailing whitespace)
        return distress_text[:start].strip()
    return distress_text.strip()

###########################
# Email Logic
###########################


def send_signup_verification_email(to_email, username, verification_token):
    subject = "Cave Country Canoes Account Verification"
    verification_link = url_for("main.verify_email", token=verification_token, _external=True)
    html_content = render_template("emails/new_customer_credentials.html",
                                   username=username,
                                   verification_link=verification_link)
    send_email(to_email, subject, html_content, html=True)

def send_verification_email_plain(to_email, username, verification_code):
    subject = "Cave Country Canoes Account Verification Code"
    body = f"""Dear {username},\n\nYour verification code is {verification_code}.\n\n- Cave Country Canoes"""
    send_email(to_email, subject, body, html=False)

def send_assignment_email_to_employee(employee, customer, emergency_id=None,
                                        location_details=None, distress_notes=None,
                                        admin_user=None, assigned=True):
    if assigned:
        if admin_user:
            subject = "New Emergency Assignment"
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
        body = f"""Dear {employee.username},

Your assignment to track Emergency Log ID {emergency_id if emergency_id else 'N/A'} has been terminated by an admin.

- Cave Country Canoes"""
        send_email(employee.email, subject, body, html=False)

def send_assignment_email_to_customer(customer, emergency_id=None,
                                        location_details=None, distress_notes=None,
                                        employee_username=None, employee_phone=None,
                                        employee_email=None, assigned=True):
    if assigned:
        subject = "Emergency Tracking Assignment"
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
        body = f"""Dear {customer.username},

Your assigned employee has been unassigned by an admin.
If you have any questions, please reach out via chat.

- Cave Country Canoes"""
        send_email(customer.email, subject, body, html=False)

def send_employee_locked_email(employee):
    subject = "Your Account Has Been Locked"
    html_content = render_template("emails/employee_locked.html",
                                   employee=employee,
                                   current_year=datetime.now().year)
    send_email(employee.email, subject, html_content, html=True)

def send_otp_email(to_email, username, otp):
    """
    Sends a formatted OTP email.
    """
    subject = "Your OTP Code for Account Update"
    # Render the HTML email template with OTP, username, and support email.
    html_content = render_template("emails/otp_email.html",
                                   username=username,
                                   otp=otp,
                                   support_email=current_app.config.get('SUPPORT_EMAIL', 'support@example.com'))
    send_email(to_email, subject, html_content, html=True)

###########################
# Blueprint Definition
###########################
bp = Blueprint("main", __name__)

###########################
# Routes / Views
###########################

@bp.route("/")
def index():
    return redirect(url_for("main.login_page"))

@bp.route("/login_page", methods=["GET", "POST"])
def login_page():
    if current_user.is_authenticated:
        if current_user.account_type in ["admin", "super_admin"]:
            return redirect(url_for("main.admin_home", st=current_user.session_token))
        elif current_user.account_type == "customer":
            return redirect(url_for("main.customer_dashboard", st=current_user.session_token))
        elif current_user.account_type == "employee":
            return redirect(url_for("main.employee_home", st=current_user.session_token))
    if request.method == "POST":
        raw_email = request.form.get("email")
        password = request.form.get("password")
        email = sanitize_input(raw_email)
        current_app.logger.debug(f"Login: raw email: {raw_email} | sanitized email: {email}")
        if is_modified(raw_email, email):
            flash("Email contains disallowed content.", "danger")
            return render_template("login.html")
        user = Users.query.filter_by(email=email).first()
        if user and not user.is_locked and user.verify_password(password):
            user.session_token = generate_unique_session_token()
            db.session.commit()
            login_user(user)
            session['session_token'] = user.session_token
            flash("Logged in successfully!", "success")
            if user.account_type in ["admin", "super_admin"]:
                return redirect(url_for("main.admin_home", st=user.session_token))
            elif user.account_type == "customer":
                return redirect(url_for("main.customer_dashboard", st=user.session_token))
            elif user.account_type == "employee":
                return redirect(url_for("main.employee_home", st=user.session_token))
        elif user and user.is_locked:
            flash("Your account is locked. Please contact support.", "danger")
        else:
            flash("Invalid email or password.", "danger")
    return render_template("login.html")

@bp.route("/api/signup", methods=["POST"])
def api_signup():
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "Invalid JSON payload."}), 400

    # Retrieve and strip raw inputs from the JSON payload
    raw_username = data.get("username", "").strip()
    raw_email = data.get("email", "").strip()
    raw_password = data.get("password", "")
    raw_phone = data.get("phone_number", "").strip()

    # Sanitize input values
    username = sanitize_input(raw_username)
    email = sanitize_input(raw_email)
    phone_number = sanitize_input(raw_phone)

    current_app.logger.debug(f"API Signup: raw username: {raw_username} | sanitized: {username}")
    current_app.logger.debug(f"API Signup: raw email: {raw_email} | sanitized: {email}")
    current_app.logger.debug(f"API Signup: raw phone: {raw_phone} | sanitized: {phone_number}")

    # Reject if any input has been altered by sanitization
    if username != raw_username or email != raw_email or phone_number != raw_phone:
        return jsonify({"success": False, "message": "Input contains disallowed HTML content."}), 400

    # Ensure all fields are provided
    if not raw_username or not raw_email or not raw_password or not raw_phone:
        return jsonify({"success": False, "message": "All fields are required."}), 400

    # Check for duplicate username or email in both Users and PendingUser
    if Users.query.filter_by(username=username).first() or PendingUser.query.filter_by(username=username).first():
        return jsonify({"success": False, "message": "Username already exists!"}), 400
    if Users.query.filter_by(email=email).first() or PendingUser.query.filter_by(email=email).first():
        return jsonify({"success": False, "message": "Email already registered."}), 400

    # Validate password to allow special characters while stripping disallowed content
    sanitized_password = bleach.clean(raw_password, tags=[], strip=True)
    current_app.logger.debug(f"API Signup: raw password provided. Sanitized version: {sanitized_password}")
    if not is_allowed_input(raw_password, sanitized_password):
        return jsonify({"success": False, "message": "Password contains disallowed content."}), 400

    # Hash the password using bcrypt
    hashed_password = bcrypt.generate_password_hash(raw_password).decode("utf-8")

    # Generate a verification token and set expiration (30 minutes)
    token = secrets.token_urlsafe(32)
    expiration = datetime.now() + timedelta(minutes=30)

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
        send_signup_verification_email(email, username, token)
        return jsonify({
            "success": True,
            "message": "Account created successfully! Please check your email to verify your account."
        }), 201
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"DB error during signup: {e}")
        return jsonify({"success": False, "message": f"Database error: {e}"}), 500




@bp.route("/signup_page", methods=["GET", "POST"])
def signup_page():
    if current_user.is_authenticated:
        if current_user.account_type in ["admin", "super_admin"]:
            return redirect(url_for("main.admin_home", st=current_user.session_token))
        elif current_user.account_type == "customer":
            return redirect(url_for("main.customer_dashboard", st=current_user.session_token))
        elif current_user.account_type == "employee":
            return redirect(url_for("main.employee_home", st=current_user.session_token))
    if request.method == "POST":
        raw_username = request.form.get("username", "").strip()
        raw_email = request.form.get("email", "").strip()
        raw_password = request.form.get("password")
        raw_phone = request.form.get("phone_number", "").strip()
        username = sanitize_input(raw_username)
        email = sanitize_input(raw_email)
        phone_number = sanitize_input(raw_phone)
        current_app.logger.debug(f"Signup: raw username: {raw_username} | sanitized: {username}")
        current_app.logger.debug(f"Signup: raw email: {raw_email} | sanitized: {email}")
        current_app.logger.debug(f"Signup: raw phone: {raw_phone} | sanitized: {phone_number}")
        if username != raw_username or email != raw_email or phone_number != raw_phone:
            flash("Input contains disallowed HTML content. Please remove it and try again.", "danger")
            return render_template("Customer/signup.html")
        sanitized_password = bleach.clean(raw_password, tags=[], strip=True)
        current_app.logger.debug(f"Signup: raw password provided. Sanitized version: {sanitized_password}")
        if not is_allowed_input(raw_password, sanitized_password):
            flash("Password contains disallowed content. Please remove any scripts and try again.", "danger")
            return render_template("Customer/signup.html")
        if not username or not email or not raw_password or not phone_number:
            flash("All fields are required.", "danger")
            return render_template("Customer/signup.html")
        if Users.query.filter_by(username=username).first() or PendingUser.query.filter_by(username=username).first():
            flash("Username already exists!", "danger")
            return render_template("Customer/signup.html")
        if Users.query.filter_by(email=email).first() or PendingUser.query.filter_by(email=email).first():
            flash("Email already registered.", "danger")
            return render_template("Customer/signup.html")
        hashed_password = bcrypt.generate_password_hash(raw_password).decode("utf-8")
        token = secrets.token_urlsafe(32)
        expiration = datetime.now() + timedelta(minutes=30)
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
            send_signup_verification_email(email, username, token)
            flash("Account created successfully! Please check your email to verify your account.", "success")
            return redirect(url_for("main.login_page"))
        except Exception as e:
            db.session.rollback()
            flash(f"Database error: {e}", "danger")
            return render_template("Customer/signup.html")
    return render_template("Customer/signup.html")

@bp.route("/api/delete_account", methods=["POST"])
@login_required
def api_delete_account():
    try:
        # Retrieve the current user record
        user = Users.query.get(current_user.user_id)
        if not user:
            return jsonify({"success": False, "message": "User not found."}), 404

        # Delete the user record
        db.session.delete(user)
        db.session.commit()

        # Log the user out and clear the session
        logout_user()
        session.clear()

        return jsonify({"success": True, "message": "Account deleted successfully."}), 200
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error deleting account for user {current_user.user_id}: {e}")
        return jsonify({"success": False, "message": "Error deleting account."}), 500



@bp.route("/verify_email/<token>", methods=["GET"])
def verify_email(token):
    pending = PendingUser.query.filter_by(token=token).first()
    if not pending:
        flash("Invalid or expired verification token.", "danger")
        return redirect(url_for("main.signup_page"))
    if pending.token_expiration < datetime.now():
        db.session.delete(pending)
        db.session.commit()
        flash("Verification token has expired. Please sign up again.", "danger")
        return redirect(url_for("main.signup_page"))
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
        current_app.logger.error(f"Email verification error: {e}")
    return redirect(url_for("main.login_page"))

@bp.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        data = request.get_json()
        raw_email = data.get("email", "")
        email = sanitize_input(raw_email)
        current_app.logger.debug(f"Forgot password: raw email: {raw_email} | sanitized: {email}")
        if is_modified(raw_email, email):
            return jsonify({"success": False, "message": "Email contains disallowed content."}), 400
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
            send_verification_email_plain(user.email, user.username, verification_code)
            return jsonify({"success": True, "message": "OTP sent to your email."}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "message": f"DB error: {e}"}), 500
    return render_template("Customer/forgot_password.html")

@bp.route("/customer_dashboard")
@login_required
def customer_dashboard():
    if current_user.account_type == "customer":
        return render_template("Customer/customer_dashboard.html", username=current_user.username)
    elif current_user.account_type in ["admin", "super_admin"]:
        return redirect(url_for("main.admin_home", st=current_user.session_token))
    else:
        return redirect(url_for("main.employee_home", st=current_user.session_token))

@bp.route("/reviews_page")
@login_required
def reviews_page():
    if current_user.account_type != "customer":
        if current_user.account_type in ["admin", "super_admin"]:
            return redirect(url_for("main.admin_home", st=current_user.session_token))
        else:
            return redirect(url_for("main.employee_home", st=current_user.session_token))
    return render_template("Customer/customer_reviews.html")

@bp.route("/submit_log_page", methods=["GET", "POST"])
@login_required
def submit_log_page():
    if current_user.account_type != "customer":
        if current_user.account_type in ["admin", "super_admin"]:
            return redirect(url_for("main.admin_home", st=current_user.session_token))
        else:
            return redirect(url_for("main.employee_home", st=current_user.session_token))
    if request.method == "POST":
        location_details = request.form.get("location_details", "").strip()
        distress_notes = request.form.get("distress_notes", "").strip()
        current_app.logger.debug(f"Submit Log: raw location: {location_details} | sanitized: {sanitize_input(location_details)}")
        current_app.logger.debug(f"Submit Log: raw distress: {distress_notes} | sanitized: {sanitize_input(distress_notes)}")
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
            return redirect(url_for("main.customer_dashboard", st=current_user.session_token))
        except Exception as e:
            db.session.rollback()
            flash(f"Database error: {e}", "danger")
            return render_template("Customer/customer_submit_log.html")
    return render_template("Customer/customer_submit_log.html")

@bp.route("/chat")
@login_required
def chat():
    return render_template("Customer/customer_chat.html",
                           username=current_user.username,
                           account_type=current_user.account_type)


##############################
#   REQUEST OTP ROUTE        #
##############################
@bp.route("/request_otp", methods=["GET", "POST"])
@login_required
def request_otp():
    if current_user.account_type != "customer":
        current_app.logger.error("HTTP 403: Forbidden access to /request_otp by user %s (%s)",
                                 current_user.username, current_user.account_type)
        flash("Only customers can request an OTP.", "danger")
        return redirect(url_for("main.login_page"))

    if request.method == "POST":
        data = request.get_json() or request.form
        raw_email = data.get("email", "").strip()
        current_app.logger.debug("Request OTP: raw email: %s | sanitized: %s",
                                 raw_email, sanitize_input(raw_email))
        if not raw_email:
            return jsonify({"success": False, "message": "Email is required."}), 400

        sanitized_email = sanitize_input(raw_email)
        if raw_email != unescape(sanitized_email):
            return jsonify({"success": False, "message": "Email contains disallowed content."}), 400

        if sanitized_email.lower() != current_user.email.lower():
            return jsonify({"success": False, "message": "Provided email does not match your account email."}), 403

        try:
            # Remove any previous OTPs for this user.
            MFA.query.filter_by(user_id=current_user.user_id).delete()
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            current_app.logger.error("Error deleting existing OTPs for user %s: %s", current_user.user_id, e)

        otp = generate_secure_otp()
        expiration = datetime.now() + timedelta(minutes=10)
        new_mfa = MFA(user_id=current_user.user_id, code=otp, expiration=expiration)
        db.session.add(new_mfa)
        try:
            db.session.commit()
            send_otp_email(current_user.email, current_user.username, otp)
            current_app.logger.info("OTP email sent to %s", current_user.email)
            return jsonify({"success": True, "message": "OTP sent to your email."}), 200
        except Exception as e:
            db.session.rollback()
            current_app.logger.error("Error sending OTP to user %s: %s", current_user.user_id, e)
            return jsonify({"success": False, "message": "Error sending OTP. Please try again later."}), 500

    # For GET, you might choose to render a template or simply return a JSON message.
    return render_template("Customer/request_otp.html")


##############################
#    OTP VERIFY ROUTE        #
##############################
@bp.route("/otp_verify", methods=["GET", "POST"])
@login_required
def otp_verify():
    if current_user.account_type != "customer":
        current_app.logger.error("HTTP 403: Forbidden access to /otp_verify by user %s (%s)",
                                 current_user.username, current_user.account_type)
        if current_user.account_type == "super_admin":
            current_user.account_type = "admin"
            db.session.commit()
            flash("Forbidden: Only customers can verify OTP. Your account has been demoted to admin.", "danger")
            return redirect(url_for("main.admin_home", st=current_user.session_token))
        elif current_user.account_type == "employee":
            flash("Forbidden: Only customers can verify OTP.", "danger")
            return redirect(url_for("main.employee_home", st=current_user.session_token))
        else:
            flash("Forbidden: Only customers can verify OTP.", "danger")
            return redirect(url_for("main.login_page"))

    if request.method == "POST":
        data = request.get_json() or request.form
        raw_otp = data.get("otp", "").strip()
        if not raw_otp:
            return jsonify({"success": False, "message": "OTP is required."}), 400

        sanitized_otp = sanitize_input(raw_otp)
        if raw_otp != unescape(sanitized_otp):
            return jsonify({"success": False, "message": "OTP contains disallowed content."}), 400

        mfa_entry = MFA.query.filter_by(user_id=current_user.user_id, code=raw_otp).first()
        if not mfa_entry or mfa_entry.expiration < datetime.now():
            return jsonify({"success": False, "message": "Invalid or expired OTP."}), 400
        try:
            db.session.delete(mfa_entry)
            db.session.commit()
            session["otp_verified"] = True
            current_app.logger.info("OTP verified for user %s", current_user.user_id)
            return jsonify({"success": True, "message": "OTP verified."}), 200
        except Exception as e:
            db.session.rollback()
            current_app.logger.error("Error removing OTP for user %s: %s", current_user.user_id, e)
            return jsonify({"success": False, "message": "Database error while verifying OTP."}), 500

    return render_template("Customer/otp_verify.html")

##############################
#    ACCOUNT UPDATE ROUTE    #
##############################
@bp.route("/account_update", methods=["GET", "POST"])
@login_required
def account_update():
    if current_user.account_type != "customer":
        current_app.logger.error("HTTP 403: Forbidden access to /account_update by user %s (%s)",
                                  current_user.username, current_user.account_type)
        flash("This resource is only for customers.", "danger")
        return redirect(url_for("main.login_page"))

    if not session.get("otp_verified"):
        flash("You must verify your OTP before updating your account.", "warning")
        return redirect(url_for("main.otp_verify", st=current_user.session_token))

    if request.method == "POST":
        data = request.get_json() or request.form
        raw_new_username = data.get("new_username", "").strip()
        raw_new_email = data.get("new_email", "").strip()
        raw_new_password = data.get("new_password", "").strip()
        raw_new_phone = data.get("new_phone", "").strip()

        # Sanitize and validate each input if provided.
        if raw_new_username:
            sanitized_username = sanitize_input(raw_new_username)
            if raw_new_username != unescape(sanitized_username):
                return jsonify({"success": False, "message": "New username contains disallowed content."}), 400
        if raw_new_email:
            sanitized_email = sanitize_input(raw_new_email)
            if raw_new_email != unescape(sanitized_email):
                return jsonify({"success": False, "message": "New email contains disallowed content."}), 400
        if raw_new_password:
            sanitized_password = sanitize_input(raw_new_password)
            if raw_new_password != unescape(sanitized_password):
                return jsonify({"success": False, "message": "New password contains disallowed content."}), 400
        if raw_new_phone:
            sanitized_phone = sanitize_input(raw_new_phone)
            if raw_new_phone != unescape(sanitized_phone):
                return jsonify({"success": False, "message": "New phone number contains disallowed content."}), 400

        if not (raw_new_username or raw_new_email or raw_new_password or raw_new_phone):
            return jsonify({"success": True, "message": "No changes made. Redirecting to dashboard."}), 200

        # Update fields if provided.
        if raw_new_username:
            if Users.query.filter(Users.username == raw_new_username, Users.user_id != current_user.user_id).first():
                return jsonify({"success": False, "message": "Username already in use."}), 400
            current_user.username = raw_new_username
        if raw_new_email:
            if Users.query.filter(Users.email == raw_new_email, Users.user_id != current_user.user_id).first():
                return jsonify({"success": False, "message": "Email already in use."}), 400
            current_user.email = raw_new_email
        if raw_new_password:
            current_user.password_hash = bcrypt.generate_password_hash(raw_new_password).decode("utf-8")
        if raw_new_phone:
            current_user.phone_number = raw_new_phone

        try:
            db.session.commit()
            session.pop("otp_verified", None)
            current_app.logger.info("Account updated for user %s", current_user.user_id)
            # If the email was changed, you might send a confirmation OTP (if desired)
            return jsonify({"success": True, "message": "Account updated successfully!"}), 200
        except Exception as e:
            db.session.rollback()
            current_app.logger.error("Database error during account update for user %s: %s", current_user.user_id, e)
            return jsonify({"success": False, "message": "Database error."}), 500

    return render_template("Customer/account_update.html")


##############################
#   DELETE ACCOUNT ROUTE     #
##############################
@bp.route("/api/delete_account", methods=["POST"])
@login_required
def delete_account_post():
    try:
        user = Users.query.get(current_user.user_id)
        if not user:
            return jsonify({"success": False, "message": "User not found."}), 404
        # Delete the user; cascades will remove related rows in chat_messages, ratings, etc.
        db.session.delete(user)
        db.session.commit()
        logout_user()
        session.clear()
        current_app.logger.info("User %s account deleted.", current_user.user_id)
        return jsonify({"success": True, "message": "Account deleted successfully."}), 200
    except Exception as e:
        db.session.rollback()
        current_app.logger.error("Error deleting account for user %s: %s", current_user.user_id, e)
        return jsonify({"success": False, "message": "Error deleting account."}), 500



@bp.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "Invalid JSON payload."}), 400
    raw_email = data.get("email", "").strip()
    password = data.get("password", "")
    email = sanitize_input(raw_email)
    current_app.logger.debug(f"API Login: raw email: {raw_email} | sanitized: {email}")
    if is_modified(raw_email, email):
        return jsonify({"success": False, "message": "Email contains disallowed content."}), 400
    if not email or not password:
        return jsonify({"success": False, "message": "Email and password are required."}), 400
    user = Users.query.filter_by(email=email).first()
    if not user or not user.verify_password(password):
        return jsonify({"success": False, "message": "Invalid email or password."}), 401
    if user.is_locked:
        return jsonify({"success": False, "message": "Your account is locked. Please contact support."}), 403
    user.session_token = generate_unique_session_token()
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        current_app.logger.error("Error generating session token for user %s: %s", user.user_id, e)
        return jsonify({"success": False, "message": "Internal server error."}), 500
    login_user(user)
    session['session_token'] = user.session_token
    return jsonify({
        "success": True,
        "message": "Logged in successfully.",
        "session_token": user.session_token,
        "account_type": user.account_type,
        "user_id": user.user_id
    }), 200


@bp.route("/api/reviews", methods=["GET", "POST"])
@login_required
def api_reviews():
    if current_user.account_type != "customer":
        return jsonify({"success": False, "message": "Unauthorized."}), 403

    if request.method == "POST":
        data = request.get_json()
        rating_header = data.get("rating_header")
        rating_notes = data.get("rating_notes")
        rating_value = data.get("rating_value")
        current_app.logger.debug(f"Review: raw header: {rating_header} | sanitized: {sanitize_input(rating_header)}")
        current_app.logger.debug(f"Review: raw notes: {rating_notes} | sanitized: {sanitize_input(rating_notes)}")

        if not rating_header or not rating_notes or rating_value is None:
            return jsonify({"success": False, "message": "All fields are required."}), 400

        sanitized_header = sanitize_input(rating_header)
        sanitized_notes = sanitize_input(rating_notes)
        if is_modified(rating_header, sanitized_header) or is_modified(rating_notes, sanitized_notes):
            return jsonify({"success": False, "message": "Review contains disallowed content."}), 400

        try:
            rating_value = int(rating_value)
            if rating_value < 1 or rating_value > 5:
                return jsonify({"success": False, "message": "Rating must be 1-5."}), 400
        except Exception:
            return jsonify({"success": False, "message": "Invalid rating value."}), 400

        new_review = Ratings(
            user_id=current_user.user_id,
            rating_header=sanitized_header,
            rating_notes=sanitized_notes,
            rating_value=rating_value
        )
        try:
            db.session.add(new_review)
            db.session.commit()
            return jsonify({"success": True, "message": "Review submitted."}), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "message": f"DB error: {e}"}), 500

    # GET request: Return current user's reviews with unique rating_id for each review.
    my_reviews = Ratings.query.filter_by(user_id=current_user.user_id).all()
    data_list = [{
        "rating_id": r.rating_id,  # Make sure your Ratings model includes this primary key
        "rating_header": r.rating_header,
        "rating_notes": r.rating_notes,
        "rating_value": r.rating_value,
        "created_at": r.created_at.strftime("%Y-%m-%d %H:%M:%S")
    } for r in my_reviews]
    return jsonify({"success": True, "reviews": data_list}), 200


@bp.route("/api/reviews/<int:review_id>", methods=["DELETE"])
@login_required
def delete_review(review_id):
    review = Ratings.query.get(review_id)
    if not review:
        return jsonify({"success": False, "message": "Review not found."}), 404
    if review.user_id != current_user.user_id:
        return jsonify({"success": False, "message": "Unauthorized to delete this review."}), 403
    try:
        db.session.delete(review)
        db.session.commit()
        return jsonify({"success": True, "message": "Review deleted successfully."}), 200
    except Exception as e:
        db.session.rollback()
        current_app.logger.error("Error deleting review for user %s: %s", current_user.user_id, e)
        return jsonify({"success": False, "message": "Database error while deleting review."}), 500


@bp.route("/api/emergency", methods=["GET", "POST"])
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
        current_app.logger.debug(f"Emergency: raw location: {location_details} | sanitized: {sanitize_input(location_details)}")
        current_app.logger.debug(f"Emergency: raw distress: {distress_notes} | sanitized: {sanitize_input(distress_notes)}")
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

@bp.route("/api/chat/messages", methods=["GET", "POST"])
@login_required
def api_chat_messages():
    if request.method == "POST":
        data = request.get_json()
        raw_message = data.get("message", "").strip()
        current_app.logger.debug(f"Chat message: raw: {raw_message} | sanitized: {sanitize_input(raw_message)}")
        if not raw_message:
            return jsonify({"success": False, "message": "Message cannot be empty."}), 400
        sanitized = sanitize_input(raw_message)
        if raw_message != unescape(sanitized):
            return jsonify({"success": False, "message": "Message contains disallowed content."}), 400
        new_msg = ChatMessages(user_id=current_user.user_id, message=raw_message)
        try:
            db.session.add(new_msg)
            db.session.commit()
            return jsonify({
                "success": True,
                "message": "Message sent successfully.",
                "timestamp": new_msg.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            }), 201
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

@bp.route("/api/user/status", methods=["GET"])
def api_user_status():
    if current_user.is_authenticated:
        return jsonify({"authenticated": True, "username": current_user.username, "user_id": current_user.user_id}), 200
    return jsonify({"authenticated": False}), 401

###########################
# ADMIN API Routes
###########################
@bp.route("/api/admin/create_employee", methods=["POST"])
@login_required
def api_admin_create_employee():
    if current_user.account_type not in ["admin", "super_admin"]:
        return jsonify({"success": False, "message": "Unauthorized. Admins only."}), 403
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    phone_number = data.get("phone_number")
    current_app.logger.debug(f"Create employee: username: {username}, email: {email}, phone: {phone_number}")
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

@bp.route("/api/admin/create_admin", methods=["POST"])
@login_required
def api_admin_create_admin():
    if current_user.account_type != "super_admin":
        current_app.logger.warning(f"User {current_user.username} attempted to create an admin without sufficient privileges.")
        return jsonify({"success": False, "message": "Root permission required to create an admin."}), 403
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    phone_number = data.get("phone_number")
    current_app.logger.debug(f"Create admin: username: {username}, email: {email}, phone: {phone_number}")
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
        current_app.logger.info(f"Super Admin {current_user.username} created a new Admin: {username}")
        return jsonify({"success": True, "message": "Admin account created successfully."}), 201
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error creating admin account: {e}")
        return jsonify({"success": False, "message": f"Database error: {e}"}), 500

@bp.route("/admin/manage_staff")
@login_required
def admin_manage_staff():
    if current_user.account_type not in ["admin", "super_admin"]:
        flash("Unauthorized access.", "danger")
        return redirect(url_for("main.login_page"))
    employees = Users.query.filter_by(account_type="employee").all()
    # Include both 'admin' and 'super_admin'
    admins = Users.query.filter(Users.account_type.in_(["admin", "super_admin"])).all()
    return render_template("Admin/admin_manage_staff.html", employees=employees, admins=admins)


@bp.route("/admin/manage_emergencies")
@login_required
def admin_manage_emergencies():
    if current_user.account_type not in ["admin", "super_admin"]:
        flash("Unauthorized access.", "danger")
        return redirect(url_for("main.login_page"))
    emergencies = Emergencies.query.all()
    # Query for all employees (or filter further if necessary)
    employees = Users.query.filter_by(account_type="employee").all()
    return render_template("Admin/admin_manage_emergencies.html", emergencies=emergencies, employees=employees)

@bp.route("/admin/chat")
@login_required
def admin_chat():
    if current_user.account_type not in ["admin", "super_admin"]:
        flash("Unauthorized access.", "danger")
        return redirect(url_for("main.login_page"))
    return render_template("Admin/admin_chat.html")

@bp.route("/api/admin/assign_emergency", methods=["POST"])
@login_required
def api_admin_assign_emergency():
    if current_user.account_type not in ["admin", "super_admin"]:
        return jsonify({"success": False, "message": "Unauthorized. Admins only."}), 403

    data = request.get_json()
    emergency_id = data.get("emergency_id")
    employee_id = data.get("employee_id")
    current_app.logger.debug(f"Assign Emergency: emergency_id: {emergency_id}, employee_id: {employee_id}")

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

    # Remove any assigned employee marker from the distress notes
    cleaned_distress_notes = remove_assigned_employee_marker(emergency.distress_notes)
    emergency.distress_notes = cleaned_distress_notes
    emergency.assigned_employee_id = employee_id

    try:
        db.session.commit()
        customer_user = Users.query.get(emergency.user_id)
        send_assignment_email_to_employee(
            employee=employee_user,
            customer=customer_user,
            emergency_id=emergency.emergency_id,
            location_details=emergency.location_details,
            distress_notes=cleaned_distress_notes,
            admin_user=current_user,
            assigned=True
        )
        send_assignment_email_to_customer(
            customer=customer_user,
            emergency_id=emergency.emergency_id,
            location_details=emergency.location_details,
            distress_notes=cleaned_distress_notes,
            employee_username=employee_user.username,
            employee_phone=employee_user.phone_number,
            employee_email=employee_user.email,
            assigned=True
        )
        return jsonify({"success": True, "message": "Assigned successfully."}), 200
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Assign Emergency Error: {e}")
        current_app.logger.error(traceback.format_exc())
        return jsonify({"success": False, "message": f"DB error: {e}"}), 500

@bp.route("/api/admin/unassign_emergency", methods=["POST"])
@login_required
def api_admin_unassign_emergency():
    if current_user.account_type not in ["admin", "super_admin"]:
        return jsonify({"success": False, "message": "Unauthorized. Admins only."}), 403

    data = request.get_json()
    emergency_id = data.get("emergency_id")
    current_app.logger.debug(f"Unassign Emergency: emergency_id: {emergency_id}")

    if not emergency_id:
        return jsonify({"success": False, "message": "emergency_id required"}), 400

    emergency = Emergencies.query.get(emergency_id)
    if not emergency:
        return jsonify({"success": False, "message": "Emergency not found."}), 404

    if emergency.assigned_employee_id is None:
        return jsonify({"success": False, "message": "No assigned employee."}), 400

    # Remove any marker from the distress notes
    cleaned_distress_notes = remove_assigned_employee_marker(emergency.distress_notes)
    emergency.distress_notes = cleaned_distress_notes
    emergency.assigned_employee_id = None

    try:
        db.session.commit()
        employee_user = Users.query.get(emergency.assigned_employee_id)
        customer_user = Users.query.get(emergency.user_id)
        if employee_user:
            send_assignment_email_to_employee(
                employee=employee_user,
                customer=customer_user,
                emergency_id=emergency.emergency_id,
                location_details=emergency.location_details,
                distress_notes=cleaned_distress_notes,
                admin_user=current_user,
                assigned=False
            )
        send_assignment_email_to_customer(
            customer=customer_user,
            emergency_id=emergency.emergency_id,
            location_details=emergency.location_details,
            distress_notes=cleaned_distress_notes,
            assigned=False
        )
        return jsonify({"success": True, "message": "Unassigned successfully."}), 200
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Unassign Emergency Error: {e}")
        current_app.logger.error(traceback.format_exc())
        return jsonify({"success": False, "message": f"DB error: {e}"}), 500

@bp.route("/api/admin/delete_staff", methods=["POST"])
@login_required
def api_admin_delete_staff():
    if current_user.account_type not in ["admin", "super_admin"]:
        return jsonify({"success": False, "message": "Unauthorized. Admins only."}), 403
    data = request.get_json()
    staff_id = data.get("staff_id")
    current_app.logger.debug(f"Delete staff request for staff_id: {staff_id}")
    if not staff_id:
        return jsonify({"success": False, "message": "Staff ID is required."}), 400
    staff = Users.query.get(staff_id)
    if not staff or staff.account_type not in ["employee", "admin"]:
        return jsonify({"success": False, "message": "Staff not found."}), 404
    try:
        db.session.delete(staff)
        db.session.commit()
        current_app.logger.info(f"Staff account {staff_id} deleted by {current_user.username}.")
        return jsonify({"success": True, "message": "Staff deleted successfully."}), 200
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error deleting staff {staff_id}: {e}")
        return jsonify({"success": False, "message": f"Database error: {e}"}), 500

@bp.route("/api/admin/update_staff/<int:staff_id>", methods=["POST"])
@login_required
def api_admin_update_staff(staff_id):
    if current_user.account_type not in ["admin", "super_admin"]:
        return jsonify({"success": False, "message": "Unauthorized. Admins only."}), 403
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    phone_number = data.get("phone_number")
    is_locked = data.get("is_locked")
    current_app.logger.debug(f"Update Staff: staff_id: {staff_id}, username: {username}, email: {email}, phone: {phone_number}")
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

@bp.route("/admin_setup", methods=["GET", "POST"])
def admin_setup():
    existing_admin = Users.query.filter_by(account_type="admin").first()
    if existing_admin:
        admin_users = Users.query.filter_by(account_type="admin").all()
        admin_emails = [admin.email for admin in admin_users]
        admin_contact_email = ", ".join(admin_emails)
        flash(f"An admin account already exists. Please contact {admin_contact_email} for admin account setup.", "info")
        return redirect(url_for("main.login_page"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        phone_number = request.form.get("phone_number", "").strip()
        provided_root_password = request.form.get("root_password", "").strip()
        current_app.logger.debug(f"Admin Setup: username: {username}, email: {email}, phone: {phone_number}")
        if not username or not email or not password or not phone_number or not provided_root_password:
            flash("All fields are required.", "error")
            return redirect(url_for("main.admin_setup"))
        # Provide a fallback of empty string if ROOT_PASSWORD is not set
        expected_root_password = (current_app.config.get("ROOT_PASSWORD") or "").strip()
        current_app.logger.debug(f"Expected ROOT_PASSWORD: {expected_root_password}")
        if provided_root_password != expected_root_password:
            flash("Invalid root password.", "error")
            return redirect(url_for("main.admin_setup"))
        if Users.query.filter_by(username=username).first():
            flash("Username already exists!", "error")
            return redirect(url_for("main.admin_setup"))
        if Users.query.filter_by(email=email).first():
            flash("Email already registered.", "error")
            return redirect(url_for("main.admin_setup"))
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
            return redirect(url_for("main.login_page"))
        except Exception as e:
            db.session.rollback()
            flash(f"Database error: {e}", "error")
            return redirect(url_for("main.admin_setup"))
    return render_template("Admin/admin_setup.html")


@bp.route("/api/elevate_super_admin", methods=["POST"])
@login_required
def api_elevate_super_admin():
    if current_user.account_type != "admin":
        return jsonify({"success": False, "message": "Unauthorized. Admins only."}), 403

    attempts = session.get("elevate_super_admin_attempts", 0)
    if attempts >= 3:
        return jsonify({"success": False, "message": "Max attempts reached. Contact existing super admin."}), 403

    existing_super_admin = Users.query.filter_by(account_type="super_admin").first()
    if existing_super_admin:
        return jsonify({"success": False, "message": "A super admin already exists."}), 403

    data = request.get_json()
    root_password = data.get("ROOT_PASSWORD", "").strip()
    # Retrieve the root password from the app's config
    expected_root_password = current_app.config.get("ROOT_PASSWORD", "").strip()
    current_app.logger.debug(f"Elevate super admin attempt: provided root password: {root_password}, expected: {expected_root_password}")

    if root_password == expected_root_password:
        try:
            current_user.account_type = "super_admin"
            db.session.commit()
            current_app.logger.info(f"User {current_user.username} elevated to super_admin.")
            return jsonify({"success": True, "message": "Elevated to super admin."}), 200
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Database error during elevation: {e}")
            return jsonify({"success": False, "message": f"Database error: {e}"}), 500
    else:
        attempts += 1
        session["elevate_super_admin_attempts"] = attempts
        if attempts >= 3:
            return jsonify({"success": False, "message": "Max attempts reached."}), 403
        else:
            return jsonify({"success": False, "message": "Incorrect root password."}), 401

@bp.route("/api/admin/lock_account", methods=["POST"])
@login_required
def api_admin_lock_account():
    if current_user.account_type not in ["admin", "super_admin"]:
        return jsonify({"success": False, "message": "Unauthorized. Admins only."}), 403
    data = request.get_json()
    user_id = data.get("user_id")
    current_app.logger.debug(f"Lock Account: user_id: {user_id}")
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
            "message": "Account locked successfully. All assigned emergencies have been unassigned and notifications sent."
        }), 200
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Database error during account lock: {str(e)}")
        return jsonify({"success": False, "message": "Server error. Please try again later."}), 500

@bp.route("/api/admin/unlock_account", methods=["POST"])
@login_required
def api_admin_unlock_account():
    if current_user.account_type not in ["admin", "super_admin"]:
        return jsonify({"success": False, "message": "Unauthorized. Admins only."}), 403
    data = request.get_json()
    user_id = data.get("user_id")
    current_app.logger.debug(f"Unlock Account: user_id: {user_id}")
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
            html_content = render_template("emails/account_unlocked.html", user=user,
                                           current_year=datetime.utcnow().year)
            send_email(to=user.email, subject="Your Account Has Been Unlocked", body=html_content, html=True)
            current_app.logger.info(f"Unlock email sent to {user.username} ({user.email}).")
        except Exception as e:
            current_app.logger.error(f"Failed to send unlock email to {user.username}: {e}")
        return jsonify({"success": True, "message": "Account unlocked successfully."}), 200
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Database error during account unlock: {str(e)}")
        return jsonify({"success": False, "message": "Server error. Please try again later."}), 500

###########################
# Employee Dashboard Routes
###########################
@bp.route("/employee/home")
@login_required
def employee_home():
    if current_user.account_type != "employee":
        flash("Unauthorized access. Redirecting to login.", "warning")
        return redirect(url_for("main.login_page"))
    return render_template("Employee/employee_home.html", username=current_user.username)

@bp.route("/employee/see_all_emergencies")
@login_required
def employee_see_all_emergencies():
    if current_user.account_type != "employee":
        flash("Unauthorized access. Redirecting to login.", "warning")
        return redirect(url_for("main.login_page"))
    all_emergencies = Emergencies.query.all()
    data = [{
        "emergency_id": emergency.emergency_id,
        "location_details": emergency.location_details,
        "distress_notes": emergency.distress_notes,
        "is_claimed": emergency.assigned_employee_id is not None,
        "claimed_by": emergency.assigned_employee.username if emergency.assigned_employee_id else None,
    } for emergency in all_emergencies]
    return render_template("Employee/see_all_emergencies.html", emergencies=data)

@bp.route("/employee/claim_emergency", methods=["POST"])
@login_required
def employee_claim_emergency():
    current_app.logger.debug(f"Employee Claim: user_id: {current_user.user_id}, account_type: {current_user.account_type}")
    if current_user.account_type != "employee":
        current_app.logger.warning(f"Unauthorized access attempt by user {current_user.username}.")
        return jsonify({"success": False, "message": "Unauthorized"}), 403
    try:
        data = request.get_json()
        current_app.logger.debug(f"Claim Emergency Data: {data}")
        emergency_id = data.get("emergency_id")
        if not emergency_id:
            current_app.logger.error("Missing emergency ID in request.")
            return jsonify({"success": False, "message": "Emergency ID is required."}), 400
        emergency = Emergencies.query.get(emergency_id)
        if not emergency:
            current_app.logger.error(f"Emergency ID {emergency_id} not found.")
            return jsonify({"success": False, "message": "Emergency not found."}), 404
        if emergency.assigned_employee_id:
            current_app.logger.info(f"Emergency ID {emergency_id} already claimed by user ID {emergency.assigned_employee_id}.")
            return jsonify({"success": False, "message": "Emergency already claimed."}), 400
        emergency.assigned_employee_id = current_user.user_id
        db.session.commit()
        customer = Users.query.get(emergency.user_id)
        if not customer:
            current_app.logger.error(f"Customer with ID {emergency.user_id} not found.")
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
        current_app.logger.info(f"Emergency ID {emergency_id} claimed successfully by {current_user.username}.")
        return jsonify({"success": True, "message": "Emergency claimed successfully."}), 200
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error claiming emergency: {str(e)}")
        return jsonify({"success": False, "message": f"An error occurred: {str(e)}"}), 500

@bp.route("/employee/resolve_emergency", methods=["POST"])
@login_required
def employee_resolve_emergency():
    if current_user.account_type != "employee":
        current_app.logger.warning(f"Unauthorized access attempt by user {current_user.username}.")
        return jsonify({"success": False, "message": "Unauthorized access."}), 403
    try:
        data = request.get_json()
        emergency_id = data.get("emergency_id")
        if not emergency_id:
            current_app.logger.error("Missing emergency ID in request.")
            return jsonify({"success": False, "message": "Emergency ID is required."}), 400
        emergency = db.session.get(Emergencies, emergency_id)
        if not emergency:
            current_app.logger.error(f"Emergency ID {emergency_id} not found.")
            return jsonify({"success": False, "message": "Emergency not found."}), 404
        if emergency.assigned_employee_id != current_user.user_id:
            current_app.logger.warning(f"User {current_user.username} is not assigned to emergency {emergency_id}.")
            return jsonify({"success": False, "message": "You are not assigned to this emergency."}), 403
        db.session.delete(emergency)
        db.session.commit()
        current_app.logger.info(f"Emergency ID {emergency_id} resolved by user {current_user.username}.")
        return jsonify({"success": True, "message": "Emergency resolved successfully."}), 200
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error while resolving emergency: {str(e)}")
        return jsonify({"success": False, "message": f"An error occurred: {str(e)}"}), 500

@bp.route("/employee/see_claimed_emergencies", methods=["GET", "POST"])
@login_required
def employee_see_claimed_emergencies():
    if current_user.account_type != "employee":
        flash("Unauthorized access. Redirecting to login.", "warning")
        return redirect(url_for("main.login_page"))
    if request.method == "POST":
        try:
            data = request.get_json()
            emergency_id = data.get("emergency_id")
            if not emergency_id:
                current_app.logger.error("Missing emergency ID in request.")
                return jsonify({"success": False, "message": "Emergency ID is required."}), 400
            emergency = db.session.get(Emergencies, emergency_id)
            if not emergency or emergency.assigned_employee_id != current_user.user_id:
                current_app.logger.warning(f"Emergency ID {emergency_id} not found or not assigned to user {current_user.username}.")
                return jsonify({"success": False, "message": "Emergency not found or not assigned to you."}), 404
            db.session.delete(emergency)
            db.session.commit()
            current_app.logger.info(f"Emergency ID {emergency_id} resolved and removed by user {current_user.username}.")
            return jsonify({"success": True, "message": "Emergency resolved and removed successfully."}), 200
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error resolving emergency: {str(e)}")
            return jsonify({"success": False, "message": f"Error: {e}"}), 500
    emergencies = Emergencies.query.filter_by(assigned_employee_id=current_user.user_id).all()
    data = [{
        "emergency_id": em.emergency_id,
        "location_details": em.location_details,
        "distress_notes": em.distress_notes,
        "customer": em.customer.username if em.customer else "Unknown",
    } for em in emergencies]
    return render_template("Employee/see_claimed_emergencies.html", emergencies=data)

@bp.route("/employee/see_all_reviews")
@login_required
def employee_see_all_reviews():
    if current_user.account_type != "employee":
        flash("Unauthorized access. Redirecting to login.", "warning")
        return redirect(url_for("main.login_page"))
    reviews = Ratings.query.all()
    data = [{
        "username": review.user.username if review.user else "Anonymous",
        "rating_header": review.rating_header,
        "rating_notes": review.rating_notes,
        "rating_value": review.rating_value,
    } for review in reviews]
    return render_template("Employee/see_all_reviews.html", reviews=data)

@bp.route("/employee/chat")
@login_required
def employee_chat():
    if current_user.account_type != "employee":
        flash("Unauthorized access. Redirecting to login.", "warning")
        return redirect(url_for("main.login_page"))
    return render_template("Employee/employee_chat.html", username=current_user.username)

@bp.route("/employee/logout", methods=["GET", "POST"])
@login_required
def employee_logout():
    logout_user()
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for("main.login_page"))

@bp.route("/logout", methods=["GET", "POST"], endpoint="logout")
@login_required
def logout():
    # If the user is a super admin, demote them to a regular admin.
    if current_user.account_type == "super_admin":
        current_user.account_type = "admin"
        db.session.commit()

    # Invalidate the session token and log the user out.
    current_user.session_token = None
    db.session.commit()
    logout_user()
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("main.login_page"))

###########################
# Email Template Routes
###########################
@bp.route("/emails/employee_locked.html")
def employee_locked_email():
    return render_template("emails/employee_locked.html")

@bp.route("/emails/account_unlocked.html")
def account_unlocked_email():
    return render_template("emails/account_unlocked.html")

@bp.route("/admin/home", endpoint="admin_home")
@login_required
def admin_home():
    if current_user.account_type not in ["admin", "super_admin"]:
        if current_user.account_type == "employee":
            return redirect(url_for("main.employee_home", st=current_user.session_token))
        return redirect(url_for("main.customer_dashboard", st=current_user.session_token))
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

@login_manager.unauthorized_handler
def unauthorized_callback():
    if request.path.startswith('/api/'):
        return jsonify({"success": False, "message": "Authentication required."}), 401
    else:
        return redirect(url_for('main.login_page'))


@bp.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    # For GET, simply render the reset password template.
    if request.method == "GET":
        return render_template("Customer/reset_password.html")

    # For POST, process the reset password request.
    data = request.get_json() or request.form
    email = data.get("email", "").strip()
    otp = data.get("otp", "").strip()
    new_password = data.get("new_password", "").strip()

    if not email or not otp or not new_password:
        return jsonify({"success": False, "message": "Email, OTP, and new password are required."}), 400

    # Sanitize the email input
    sanitized_email = sanitize_input(email)
    if email != unescape(sanitized_email):
        return jsonify({"success": False, "message": "Email contains disallowed content."}), 400

    # Look up the user by email
    user = Users.query.filter_by(email=email).first()
    if not user:
        return jsonify({"success": False, "message": "User not found."}), 404

    # Look up the OTP entry for the user
    mfa_entry = MFA.query.filter_by(user_id=user.user_id, code=otp).first()
    if not mfa_entry or mfa_entry.expiration < datetime.now():
        return jsonify({"success": False, "message": "Invalid or expired OTP."}), 400

    # Update the user's password
    try:
        user.password_hash = bcrypt.generate_password_hash(new_password).decode("utf-8")
        # Remove the used OTP entry
        db.session.delete(mfa_entry)
        db.session.commit()
        return jsonify({"success": True, "message": "Password reset successfully."}), 200
    except Exception as e:
        db.session.rollback()
        current_app.logger.error("Error resetting password for user %s: %s", user.user_id, e)
        return jsonify({"success": False, "message": "Error resetting password."}), 500


@bp.app_context_processor
def inject_globals():
    from flask_login import current_user
    return {
        "session_token": current_user.session_token if current_user.is_authenticated else "",
        "datetime": datetime,
        "debug": current_app.config.get("DEBUG", True)
    }