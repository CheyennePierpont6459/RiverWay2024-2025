from flask import render_template, redirect, url_for, flash, request, abort
from flask_login import login_user, logout_user, login_required, current_user
from .forms import (RegistrationForm, LoginForm, EmployeeCreationForm, RouteForm,
                    PointOfInterestForm, GeofenceForm, TripRequestForm, DistressAlertForm)
from .models import (db, Account, Customer, Employee, Permissions, LocationsOfInterest,
                     Route, TripType, Trip, CustomerTrip, PointsOfInterest, Geofences,
                     EmergencyDistressAlerts, EmergencyDistressAssignmentQueue, ActivityLog)
from werkzeug.security import generate_password_hash
from .utils import admin_required, super_admin_required, employee_required
from datetime import datetime

from . import create_app
app = create_app()

@app.route('/')
def index():
    return redirect(url_for('login'))

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

        new_customer = Customer(
            CustomerID=new_user.AccountID
        )
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
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# User Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = Account.query.filter_by(Username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            flash('Login successful.', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html', form=form)

# User Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# User Dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_super_admin:
        return redirect(url_for('super_admin_dashboard'))
    elif current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    elif current_user.is_employee:
        return redirect(url_for('employee_dashboard'))
    else:
        return redirect(url_for('customer_dashboard'))

# Admin Dashboard
@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    return render_template('admin/dashboard.html')

# Super Admin Dashboard
@app.route('/super_admin/dashboard')
@login_required
@super_admin_required
def super_admin_dashboard():
    return render_template('admin/dashboard.html')  # Reuse admin dashboard template

# Employee Dashboard
@app.route('/employee/dashboard')
@login_required
@employee_required
def employee_dashboard():
    return render_template('employee/dashboard.html')

# Customer Dashboard
@app.route('/customer/dashboard')
@login_required
def customer_dashboard():
    return render_template('customer/dashboard.html')

# Admin creating employee accounts
@app.route('/admin/create_employee', methods=['GET', 'POST'])
@login_required
@admin_required
def create_employee():
    form = EmployeeCreationForm()
    if form.validate_on_submit():
        temp_password = 'password123'  # Generate a secure temporary password
        hashed_password = generate_password_hash(temp_password)
        new_account = Account(
            Username=form.username.data,
            PasswordHash=hashed_password,
            Email=form.email.data,
            FirstName=form.first_name.data,
            LastName=form.last_name.data,
            AccountType='Employee',
            PermissionTier=form.permission_tier.data
        )
        db.session.add(new_account)
        db.session.commit()

        new_employee = Employee(
            EmployeeID=new_account.AccountID,
            Position=form.position.data
        )
        db.session.add(new_employee)
        db.session.commit()

        # Log the activity
        activity_log = ActivityLog(
            ActivityType='Employee Account Creation',
            TableName='Employee',
            RecordID=new_employee.EmployeeID,
            OperationType='INSERT',
            Description=f'Admin {current_user.Username} created employee account for {new_account.Username} with position {new_employee.Position} and permission tier {new_account.PermissionTier}.',
            Username=current_user.Username
        )
        db.session.add(activity_log)
        db.session.commit()

        flash(f'Employee account created successfully. Temporary password is {temp_password}', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('admin/create_employee.html', form=form)

# Admin managing routes
@app.route('/admin/manage_routes', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_routes():
    form = RouteForm()
    locations = LocationsOfInterest.query.all()
    form.start_location_id.choices = [(loc.LocationID, loc.Name) for loc in locations]
    form.end_location_id.choices = [(loc.LocationID, loc.Name) for loc in locations]

    if form.validate_on_submit():
        new_route = Route(
            StartLocationID=form.start_location_id.data,
            EndLocationID=form.end_location_id.data,
            Distance=form.distance.data,
            EstimatedTime=form.estimated_time.data,
            DifficultyLevel=form.difficulty_level.data,
            AgeRequirement=form.age_requirement.data
        )
        db.session.add(new_route)
        db.session.commit()

        # Log the activity
        activity_log = ActivityLog(
            ActivityType='Route Creation',
            TableName='Route',
            RecordID=new_route.RouteID,
            OperationType='INSERT',
            Description=f'New route created from {new_route.start_location.Name} to {new_route.end_location.Name} by admin {current_user.Username}.',
            Username=current_user.Username
        )
        db.session.add(activity_log)
        db.session.commit()

        flash('Route created successfully.', 'success')
        return redirect(url_for('manage_routes'))

    routes = Route.query.all()
    return render_template('admin/manage_routes.html', form=form, routes=routes)

# Admin managing points of interest
@app.route('/admin/manage_poi', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_poi():
    form = PointOfInterestForm()
    routes = Route.query.all()
    form.route_id.choices = [(route.RouteID, f'Route {route.RouteID}') for route in routes]

    if form.validate_on_submit():
        new_poi = PointsOfInterest(
            Name=form.name.data,
            Description=form.description.data,
            Latitude=form.latitude.data,
            Longitude=form.longitude.data,
            RouteID=form.route_id.data,
            Type=form.type.data
        )
        db.session.add(new_poi)
        db.session.commit()

        # Log the activity
        activity_log = ActivityLog(
            ActivityType='Point of Interest Creation',
            TableName='PointsOfInterest',
            RecordID=new_poi.POIID,
            OperationType='INSERT',
            Description=f'New point of interest "{new_poi.Name}" created by admin {current_user.Username}.',
            Username=current_user.Username
        )
        db.session.add(activity_log)
        db.session.commit()

        flash('Point of Interest created successfully.', 'success')
        return redirect(url_for('manage_poi'))

    pois = PointsOfInterest.query.all()
    return render_template('admin/manage_poi.html', form=form, pois=pois)

# Admin managing geofences
@app.route('/admin/manage_geofences', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_geofences():
    form = GeofenceForm()
    pois = PointsOfInterest.query.all()
    form.poi_id.choices = [(poi.POIID, poi.Name) for poi in pois]

    if form.validate_on_submit():
        new_geofence = Geofences(
            POIID=form.poi_id.data,
            Radius=form.radius.data,
            AlertType=form.alert_type.data
        )
        db.session.add(new_geofence)
        db.session.commit()

        # Log the activity
        activity_log = ActivityLog(
            ActivityType='Geofence Creation',
            TableName='Geofences',
            RecordID=new_geofence.GeofenceID,
            OperationType='INSERT',
            Description=f'New geofence created for POI ID {new_geofence.POIID} by admin {current_user.Username}.',
            Username=current_user.Username
        )
        db.session.add(activity_log)
        db.session.commit()

        flash('Geofence created successfully.', 'success')
        return redirect(url_for('manage_geofences'))

    geofences = Geofences.query.all()
    return render_template('admin/manage_geofences.html', form=form, geofences=geofences)

# Employee viewing and moderating trips
@app.route('/employee/trips')
@login_required
@employee_required
def employee_trips():
    trips = Trip.query.all()
    return render_template('employee/trips.html', trips=trips)

# Employee removing customers from trips
@app.route('/employee/trips/<int:trip_id>/remove_customer/<int:customer_id>', methods=['POST'])
@login_required
@employee_required
def remove_customer_from_trip(trip_id, customer_id):
    customer_trip = CustomerTrip.query.filter_by(TripID=trip_id, CustomerID=customer_id).first()
    if customer_trip:
        db.session.delete(customer_trip)
        db.session.commit()
        # Log the activity
        activity_log = ActivityLog(
            ActivityType='Customer Removal from Trip',
            TableName='CustomerTrip',
            RecordID=customer_trip.CustomerTripID,
            OperationType='DELETE',
            Description=f'Employee {current_user.Username} removed customer ID {customer_id} from trip ID {trip_id}.',
            Username=current_user.Username
        )
        db.session.add(activity_log)
        db.session.commit()
        flash('Customer removed from trip.', 'success')
    else:
        flash('Customer not found in this trip.', 'danger')
    return redirect(url_for('employee_trips'))

# Employee handling distress calls
@app.route('/employee/distress_calls')
@login_required
@employee_required
def distress_calls():
    alerts = EmergencyDistressAlerts.query.filter_by(Status='Pending').all()
    return render_template('employee/distress_calls.html', alerts=alerts)

# Employee assigning distress call
@app.route('/employee/assign_distress_call/<int:alert_id>', methods=['POST'])
@login_required
@employee_required
def assign_distress_call(alert_id):
    alert = EmergencyDistressAlerts.query.get_or_404(alert_id)
    alert.Status = 'Assigned'
    alert.AssignedEmployeeID = current_user.AccountID
    alert.ResponseTime = datetime.utcnow()
    db.session.commit()
    # Log the activity
    activity_log = ActivityLog(
        ActivityType='Distress Call Assignment',
        TableName='EmergencyDistressAlerts',
        RecordID=alert.AlertID,
        OperationType='UPDATE',
        Description=f'Employee {current_user.Username} assigned distress call ID {alert.AlertID} to themselves.',
        Username=current_user.Username
    )
    db.session.add(activity_log)
    db.session.commit()
    flash('Distress call assigned to you.', 'success')
    return redirect(url_for('distress_calls'))

# Customer requesting a trip
@app.route('/customer/request_trip', methods=['GET', 'POST'])
@login_required
def request_trip():
    form = TripRequestForm()
    routes = Route.query.all()
    trip_types = TripType.query.all()
    form.route_id.choices = [(route.RouteID, f'Route {route.RouteID}') for route in routes]
    form.trip_type_id.choices = [(tt.TripTypeID, tt.TypeName) for tt in trip_types]

    if form.validate_on_submit():
        new_trip = Trip(
            RouteID=form.route_id.data,
            TripTypeID=form.trip_type_id.data,
            TripDate=form.trip_date.data
        )
        db.session.add(new_trip)
        db.session.commit()

        customer_trip = CustomerTrip(
            CustomerID=current_user.AccountID,
            TripID=new_trip.TripID
        )
        db.session.add(customer_trip)
        db.session.commit()

        # Log the activity
        activity_log = ActivityLog(
            ActivityType='Trip Request',
            TableName='Trip',
            RecordID=new_trip.TripID,
            OperationType='INSERT',
            Description=f'Customer {current_user.Username} requested a new trip ID {new_trip.TripID}.',
            Username=current_user.Username
        )
        db.session.add(activity_log)
        db.session.commit()

        flash('Trip requested successfully.', 'success')
        return redirect(url_for('customer_trips'))

    return render_template('customer/request_trip.html', form=form)

# Customer viewing trips
@app.route('/customer/trips')
@login_required
def customer_trips():
    customer_trips = CustomerTrip.query.filter_by(CustomerID=current_user.AccountID).all()
    return render_template('customer/trips.html', customer_trips=customer_trips)

# Error Handlers
@app.errorhandler(403)
def forbidden(e):
    return render_template('errors/403.html'), 403

@app.errorhandler(404)
def page_not_found(e):
    return render_template('errors/404.html'), 404
