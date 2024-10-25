from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from extensions import RegistrationForm, LoginForm
from .models import db, Account, Customer, ActivityLog
from werkzeug.security import generate_password_hash
from datetime import datetime
from flask import Blueprint

app = Blueprint('app', __name__)

# Home route, redirect to login
@app.route('/')
def index():
    return redirect(url_for('app.login'))

# User Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        new_user = Account(
            Username=form.username.data,
            PasswordHash=hashed_password,
            Email=form.email.data,
            FirstName=form.first_name.data,
            LastName=form.last_name.data,
            AccountType=form.account_type.data,
            PermissionTier=1  # Default permission for customers
        )
        db.session.add(new_user)
        db.session.commit()

        new_customer = Customer(CustomerID=new_user.AccountID)
        db.session.add(new_customer)
        db.session.commit()

        # Log the activity
        activity_log = ActivityLog(
            ActivityType='Account Creation',
            TableName='Account',
            RecordID=new_user.AccountID,
            OperationType='INSERT',
            Description=f'New customer account created for username {new_user.Username}.',
            Username='SYSTEM'
        )
        db.session.add(activity_log)
        db.session.commit()

        flash('Account created successfully. Please log in.', 'success')
        return redirect(url_for('app.login'))
    return render_template('register.html', form=form)

# User Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('app.dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = Account.query.filter_by(Username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            flash('Login successful.', 'success')
            return redirect(url_for('app.dashboard'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html', form=form)

# User Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('app.login'))

# Dashboard redirection based on user type
@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_super_admin:
        return redirect(url_for('app.super_admin_dashboard'))
    elif current_user.is_admin:
        return redirect(url_for('app.admin_dashboard'))
    elif current_user.is_employee:
        return redirect(url_for('app.employee_dashboard'))
    else:
        return redirect(url_for('app.customer_dashboard'))

# Admin Dashboard
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    return render_template('admin/dashboard.html')

# Super Admin Dashboard
@app.route('/super_admin/dashboard')
@login_required
def super_admin_dashboard():
    return render_template('admin/dashboard.html')

# Employee Dashboard
@app.route('/employee/dashboard')
@login_required
def employee_dashboard():
    return render_template('employee/dashboard.html')

# Customer Dashboard
@app.route('/customer/dashboard')
@login_required
def customer_dashboard():
    return render_template('customer/dashboard.html')
