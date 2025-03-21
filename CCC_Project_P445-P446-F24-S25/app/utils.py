"""
Utility functions' module.

Provides helper functions for:
- Generating secure OTPs
- Retrieving the local IP address
- Purging expired pending users
- Sending emails and verification emails
- Input sanitization and helper functions for processing distress notes
"""
import ssl
import traceback
from email.message import EmailMessage

import bleach
import hashlib
import socket
import secrets
import smtplib

from datetime import datetime, timezone
from flask import current_app
from .models import PendingUser
from .extensions import db

def generate_secure_otp():
    random_bytes = secrets.token_bytes(16)
    return hashlib.sha256(random_bytes).hexdigest()[:6].upper()

def get_local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
    except OSError:
        local_ip = "127.0.0.1"
    return local_ip

def purge_expired_pending_users():
    now = datetime.now(timezone.utc)
    expired = PendingUser.query.filter(PendingUser.token_expiration < now).all()
    for user in expired:
        db.session.delete(user)
    db.session.commit()

def send_verification_email(to_email, username, verification_code):
    subject = "CCC Emergency Map Account Verification Code"
    body = (
        f"Dear {username},\n\n"
        f"Your verification code is {verification_code}.\n\n"
        "- CCC Emergency Map Team"
    )
    send_email(to_email, subject, body, html=False)

def sanitize_input(input_str):
    """Sanitizes input using bleach (removes all HTML)."""
    if input_str is None:
        return None

    return bleach.clean(input_str, tags=[], attributes={}, strip=True)

def contains_script_tags(input_str):
    if not input_str:
        return False
    sanitized = sanitize_input(input_str)
    return sanitized != input_str

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
    """
       Removes any existing assigned employee marker from the distress notes,
       and appends a new marker if new_employee_id is provided.
    """
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


def send_email(to, subject, body, html=False):
    # Ensure required configuration keys are present.
    required_keys = ['MAIL_SERVER', 'MAIL_PORT', 'MAIL_USERNAME', 'MAIL_PASSWORD']
    missing = [key for key in required_keys if not current_app.config.get(key)]
    if missing:
        raise Exception("Email configuration is incomplete: Missing " + ", ".join(missing))

    # Retrieve configuration values.
    mail_server = current_app.config['MAIL_SERVER']
    mail_port = current_app.config['MAIL_PORT']
    mail_username = current_app.config['MAIL_USERNAME']
    mail_password = current_app.config['MAIL_PASSWORD']

    # Use MAIL_DEFAULT_SENDER if set; otherwise, fallback to mail_username.
    sender_tuple = current_app.config.get('MAIL_DEFAULT_SENDER')
    if sender_tuple and sender_tuple[1]:
        sender = sender_tuple[1]
    else:
        sender = mail_username

    msg = EmailMessage()
    msg["From"] = sender
    if isinstance(to, str):
        to = [to]
    msg["To"] = ", ".join(to)
    msg["Subject"] = subject

    if html:
        msg.set_content(body)
        msg.add_alternative(body, subtype='html')
    else:
        msg.set_content(body)

    try:
        if current_app.config.get('MAIL_USE_TLS'):
            with smtplib.SMTP(mail_server, mail_port) as smtp:
                smtp.ehlo()
                smtp.starttls(context=ssl.create_default_context())
                smtp.ehlo()
                smtp.login(mail_username, mail_password)
                smtp.send_message(msg)
        elif current_app.config.get('MAIL_USE_SSL'):
            with smtplib.SMTP_SSL(mail_server, mail_port, context=ssl.create_default_context()) as smtp:
                smtp.login(mail_username, mail_password)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(mail_server, mail_port) as smtp:
                smtp.login(mail_username, mail_password)
                smtp.send_message(msg)
        current_app.logger.info("Email sent to %s with subject '%s'.", ", ".join(to), subject)
    except Exception as e:
        current_app.logger.error("Failed to send email to %s: %s", ", ".join(to), e)
        current_app.logger.error(traceback.format_exc())
        raise