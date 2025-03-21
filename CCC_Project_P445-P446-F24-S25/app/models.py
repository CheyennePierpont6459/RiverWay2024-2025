"""
Database models module.

Defines all SQLAlchemy models used in the application including:
- Users
- EmailVerification
- PendingUser
- Ratings
- Emergencies
- ChatMessages
- MFA
"""

from datetime import datetime, timezone
from flask_login import UserMixin
from .extensions import db, bcrypt

class Users(db.Model, UserMixin):
    __tablename__ = "users"
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    account_type = db.Column(db.String(20), nullable=False, default="customer")
    is_locked = db.Column(db.Boolean, nullable=False, default=False)
    session_token = db.Column(db.String(64), nullable=True, unique=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    email_verified = db.Column(db.Boolean, nullable=False, default=False)

    @property
    def id(self):
        return self.user_id

    def verify_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    # Relationships with cascade and passive deletes
    assigned_emergencies = db.relationship(
        "Emergencies", back_populates="assigned_employee",
        lazy=True, foreign_keys="Emergencies.assigned_employee_id",
        cascade="all, delete-orphan", passive_deletes=True
    )
    emergencies_created = db.relationship(
        "Emergencies", back_populates="customer",
        lazy=True, foreign_keys="Emergencies.user_id",
        cascade="all, delete-orphan", passive_deletes=True
    )
    chat_messages = db.relationship(
        "ChatMessages", back_populates="user",
        lazy=True, cascade="all, delete-orphan", passive_deletes=True
    )
    ratings = db.relationship(
        "Ratings", back_populates="user",
        lazy=True, cascade="all, delete-orphan", passive_deletes=True
    )
    mfa_records = db.relationship(
        "MFA", back_populates="user",
        lazy=True, cascade="all, delete-orphan", passive_deletes=True
    )

class EmailVerification(db.Model):
    __tablename__ = "email_verifications"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False, unique=True)
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
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    token = db.Column(db.String(128), nullable=False, unique=True)
    token_expiration = db.Column(db.DateTime, nullable=False)

class Ratings(db.Model):
    __tablename__ = "ratings"
    rating_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer,
                        db.ForeignKey("users.user_id", ondelete="CASCADE", onupdate="CASCADE"),
                        nullable=False)
    rating_header = db.Column(db.String(100), nullable=False)
    rating_notes = db.Column(db.Text, nullable=False)
    rating_value = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    user = db.relationship("Users", back_populates="ratings")

class Emergencies(db.Model):
    __tablename__ = "emergencies"
    emergency_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer,
                        db.ForeignKey("users.user_id", ondelete="CASCADE", onupdate="CASCADE"),
                        nullable=False)
    location_details = db.Column(db.Text, nullable=True)
    distress_notes = db.Column(db.Text, nullable=True)
    assigned_employee_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    assigned_employee = db.relationship(
        "Users", back_populates="assigned_emergencies",
        foreign_keys=[assigned_employee_id]
    )
    customer = db.relationship(
        "Users", back_populates="emergencies_created",
        foreign_keys=[user_id]
    )

    @property
    def customer_name(self):
        return self.customer.username if self.customer else "Unknown"

    @property
    def customer_phone(self):
        return self.customer.phone_number if self.customer else "N/A"

    @property
    def assigned_employee_name(self):
        return self.assigned_employee.username if self.assigned_employee else "Unassigned"

class ChatMessages(db.Model):
    __tablename__ = "chat_messages"
    message_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer,
                        db.ForeignKey("users.user_id", ondelete="CASCADE", onupdate="CASCADE"),
                        nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    user = db.relationship("Users", back_populates="chat_messages")

class MFA(db.Model):
    __tablename__ = "mfa"
    mfa_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False)
    code = db.Column(db.String(6), nullable=False)
    expiration = db.Column(db.DateTime, nullable=False)
    user = db.relationship("Users", back_populates="mfa_records")
