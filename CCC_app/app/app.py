# app.py
from flask import Flask, render_template, request, redirect, url_for, flash
from extensions import db, login_manager
from models import Account, Customer, Employee, EmergencyDistressAlert, PointsOfInterest, CustomerFeedback, Trip, CustomerTrip, Route
from decorators import admin_required, super_admin_required, employee_required
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:Preston-2020d@localhost/ccc_emergency_map'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'  # Redirects to login page if not logged in

@login_manager.user_loader
def load_user(user_id):
    return Account.query.get(int(user_id))

# Role-based Dashboard Routing
def route_by_role(account_type):
    if account_type == 'Customer':
        return 'customer_dashboard'
    elif account_type == 'Employee':
        return 'employee_dashboard'
    elif account_type == 'Admin':
        return 'admin_dashboard'
    elif account_type == 'Super Admin':
        return 'super_admin_dashboard'
    return 'login'

# Login Route
@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    message = ''
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Query MySQL database for user
        user = Account.query.filter_by(Email=email).first()

        # Validate user credentials
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for(route_by_role(user.AccountType)))
        else:
            message = 'Incorrect email or password!'
    return render_template('login.html', message=message)

# Registration Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    message = ''
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        account_type = 'Customer'  # Only allow customer registration

        # Validate form input
        account = Account.query.filter_by(Email=email).first()

        if account:
            message = 'Account already exists!'
        elif not first_name or not password or not email:
            message = 'Please fill out the form completely!'
        else:
            # Hash the password and insert the new user into the database
            hashed_password = generate_password_hash(password)
            # Set PermissionTier based on account_type
            permission_tiers = {'Customer': 1}
            permission_tier = permission_tiers.get(account_type, 1)

            new_account = Account(
                Username=email,
                PasswordHash=hashed_password,
                Email=email,
                FirstName=first_name,
                LastName=last_name,
                AccountType=account_type,
                PermissionTier=permission_tier
            )
            db.session.add(new_account)
            db.session.commit()

            # Create corresponding Customer record
            new_customer = Customer(CustomerID=new_account.AccountID)
            db.session.add(new_customer)
            db.session.commit()

            flash('You have successfully registered!', 'success')
            return redirect(url_for('login'))
    return render_template('register.html', message=message)

# Customer Dashboard
@app.route('/customer_dashboard')
@login_required
def customer_dashboard():
    if current_user.AccountType == 'Customer':
        customer_trip = CustomerTrip.query.filter_by(CustomerID=current_user.AccountID, CheckedIn=False).first()
        return render_template('customer_dashboard.html', name=current_user.FirstName, customer_trip=customer_trip)
    flash('Unauthorized access.', 'danger')
    return redirect(url_for('login'))

# Customer Check-In
@app.route('/check_in', methods=['GET', 'POST'])
@login_required
def check_in():
    if current_user.AccountType == 'Customer':
        if request.method == 'POST':
            # Simulate checking in by creating a CustomerTrip
            trip_id = request.form['trip_id']
            customer_trip = CustomerTrip(CustomerID=current_user.AccountID, TripID=trip_id, CheckedIn=True)
            db.session.add(customer_trip)
            db.session.commit()
            flash('Checked in successfully!', 'success')
            return redirect(url_for('customer_dashboard'))

        # Display available trips
        trips = Trip.query.all()
        return render_template('check_in.html', trips=trips)
    flash('Unauthorized access.', 'danger')
    return redirect(url_for('login'))

# Send Emergency Ping
@app.route('/emergency_ping', methods=['GET', 'POST'])
@login_required
def emergency_ping():
    if current_user.AccountType == 'Customer':
        if request.method == 'POST':
            latitude = request.form['latitude']
            longitude = request.form['longitude']
            severity = request.form['severity']

            alert = EmergencyDistressAlert(
                CustomerID=current_user.AccountID,
                Latitude=latitude,
                Longitude=longitude,
                SeverityLevel=severity,
                Status='Pending'
            )
            db.session.add(alert)
            db.session.commit()
            flash('Emergency ping sent successfully!', 'success')
            return redirect(url_for('customer_dashboard'))
        return render_template('emergency_ping.html')
    flash('Unauthorized access.', 'danger')
    return redirect(url_for('login'))

# View Points of Interest
@app.route('/points_of_interest')
@login_required
def points_of_interest():
    if current_user.AccountType == 'Customer':
        pois = PointsOfInterest.query.all()
        return render_template('points_of_interest.html', pois=pois)
    flash('Unauthorized access.', 'danger')
    return redirect(url_for('login'))

# Leave a Review
@app.route('/leave_review', methods=['GET', 'POST'])
@login_required
def leave_review():
    if current_user.AccountType == 'Customer':
        if request.method == 'POST':
            feedback = request.form['feedback']
            rating = request.form['rating']
            customer_feedback = CustomerFeedback(
                CustomerID=current_user.AccountID,
                Feedback=feedback,
                Rating=rating
            )
            db.session.add(customer_feedback)
            db.session.commit()
            flash('Feedback submitted successfully!', 'success')
            return redirect(url_for('customer_dashboard'))
        return render_template('leave_review.html')
    flash('Unauthorized access.', 'danger')
    return redirect(url_for('login'))

# Employee Dashboard
@app.route('/employee_dashboard')
@login_required
def employee_dashboard():
    if current_user.AccountType in ['Employee', 'Admin', 'Super Admin']:
        # Display distress alerts assigned to employee
        assigned_alerts = EmergencyDistressAlert.query.filter_by(AssignedEmployeeID=current_user.AccountID, Status='Assigned').all()
        # Display all pending distress alerts
        pending_alerts = EmergencyDistressAlert.query.filter_by(Status='Pending').all()
        return render_template('employee_dashboard.html', name=current_user.FirstName, assigned_alerts=assigned_alerts, pending_alerts=pending_alerts)
    flash('Unauthorized access.', 'danger')
    return redirect(url_for('login'))

# Confirm Customer is Safe
@app.route('/confirm_customer_safe/<int:alert_id>')
@login_required
def confirm_customer_safe(alert_id):
    if current_user.AccountType in ['Employee', 'Admin', 'Super Admin']:
        alert = EmergencyDistressAlert.query.get(alert_id)
        if alert:
            alert.Status = 'Resolved'
            alert.ResolutionTime = datetime.utcnow()
            db.session.commit()
            flash('Customer marked as safe.', 'success')
        else:
            flash('Alert not found.', 'danger')
        return redirect(url_for('employee_dashboard'))
    flash('Unauthorized access.', 'danger')
    return redirect(url_for('login'))

# Assign Alert to Employee
@app.route('/assign_alert/<int:alert_id>')
@login_required
def assign_alert(alert_id):
    if current_user.AccountType in ['Employee', 'Admin', 'Super Admin']:
        alert = EmergencyDistressAlert.query.get(alert_id)
        if alert and alert.Status == 'Pending':
            alert.Status = 'Assigned'
            alert.AssignedEmployeeID = current_user.AccountID
            alert.ResponseTime = datetime.utcnow()
            db.session.commit()
            flash('Alert assigned to you.', 'success')
        else:
            flash('Alert not found or already assigned.', 'danger')
        return redirect(url_for('employee_dashboard'))
    flash('Unauthorized access.', 'danger')
    return redirect(url_for('login'))

# View Customer Feedback
@app.route('/view_feedback')
@login_required
def view_feedback():
    if current_user.AccountType in ['Employee', 'Admin', 'Super Admin']:
        feedbacks = CustomerFeedback.query.all()
        return render_template('view_feedback.html', feedbacks=feedbacks)
    flash('Unauthorized access.', 'danger')
    return redirect(url_for('login'))

# Create Trip
@app.route('/create_trip', methods=['GET', 'POST'])
@login_required
def create_trip():
    if current_user.AccountType in ['Employee', 'Admin', 'Super Admin']:
        if request.method == 'POST':
            route_id = request.form['route_id']
            total_distance = request.form['total_distance']
            trip = Trip(RouteID=route_id, TotalDistance=total_distance)
            db.session.add(trip)
            db.session.commit()
            flash('Trip created successfully!', 'success')
            return redirect(url_for('employee_dashboard'))
        routes = Route.query.all()
        return render_template('create_trip.html', routes=routes)
    flash('Unauthorized access.', 'danger')
    return redirect(url_for('login'))

# Admin Dashboard
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.AccountType in ['Admin', 'Super Admin']:
        return render_template('admin_dashboard.html', name=current_user.FirstName)
    flash('Unauthorized access.', 'danger')
    return redirect(url_for('login'))

# Create Employee Account
@app.route('/create_employee', methods=['GET', 'POST'])
@login_required
def create_employee():
    if current_user.AccountType in ['Admin', 'Super Admin']:
        if request.method == 'POST':
            first_name = request.form['first_name']
            last_name = request.form['last_name']
            email = request.form['email']
            password = request.form['password']
            position = request.form['position']

            account = Account.query.filter_by(Email=email).first()
            if account:
                flash('Account already exists!', 'danger')
            else:
                hashed_password = generate_password_hash(password)
                new_account = Account(
                    Username=email,
                    PasswordHash=hashed_password,
                    Email=email,
                    FirstName=first_name,
                    LastName=last_name,
                    AccountType='Employee',
                    PermissionTier=2
                )
                db.session.add(new_account)
                db.session.commit()

                new_employee = Employee(
                    EmployeeID=new_account.AccountID,
                    Position=position
                )
                db.session.add(new_employee)
                db.session.commit()
                flash('Employee account created successfully!', 'success')
                return redirect(url_for('admin_dashboard'))
        return render_template('create_employee.html')
    flash('Unauthorized access.', 'danger')
    return redirect(url_for('login'))

# Create Route
@app.route('/create_route', methods=['GET', 'POST'])
@login_required
def create_route():
    if current_user.AccountType in ['Admin', 'Super Admin']:
        if request.method == 'POST':
            distance = request.form['distance']
            difficulty = request.form['difficulty']
            age_requirement = request.form['age_requirement']
            route = Route(
                Distance=distance,
                DifficultyLevel=difficulty,
                AgeRequirement=age_requirement
            )
            db.session.add(route)
            db.session.commit()
            flash('Route created successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        return render_template('create_route.html')
    flash('Unauthorized access.', 'danger')
    return redirect(url_for('login'))

# Create Point of Interest
@app.route('/create_poi', methods=['GET', 'POST'])
@login_required
def create_poi():
    if current_user.AccountType in ['Admin', 'Super Admin']:
        if request.method == 'POST':
            name = request.form['name']
            description = request.form['description']
            latitude = request.form['latitude']
            longitude = request.form['longitude']
            poi_type = request.form['type']
            poi = PointsOfInterest(
                Name=name,
                Description=description,
                Latitude=latitude,
                Longitude=longitude,
                Type=poi_type
            )
            db.session.add(poi)
            db.session.commit()
            flash('Point of interest created successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        return render_template('create_poi.html')
    flash('Unauthorized access.', 'danger')
    return redirect(url_for('login'))

# Super Admin Dashboard
@app.route('/super_admin_dashboard')
@login_required
def super_admin_dashboard():
    if current_user.AccountType == 'Super Admin':
        return render_template('super_admin_dashboard.html', name=current_user.FirstName)
    flash('Unauthorized access.', 'danger')
    return redirect(url_for('login'))

# Logout Route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Run the Flask app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)