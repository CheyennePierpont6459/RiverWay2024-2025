from flask import Blueprint, render_template, redirect, url_for, flash, request 

from flask_login import login_required, current_user 

from decorators import permission_required 

from models import db, Trip, EmergencyDistressAlerts, CustomerFeedback, Route, LocationsOfInterest 

from forms import TripForm 

employee_blueprint = Blueprint('employee', __name__, template_folder='templates/employee') 

@employee_blueprint.route('/') 

@login_required 

@permission_required(2) 

def index(): 

    return render_template('employee/index.html') 

@employee_blueprint.route('/manage_trips', methods=['GET', 'POST']) 

@login_required 

@permission_required(2) 

def manage_trips(): 

    form = TripForm() 

    if form.validate_on_submit(): 

        # Create a new trip 

        trip = Trip( 

            RouteID=form.route_id.data, 

            TripTypeID=form.trip_type_id.data, 

            TripDate=form.trip_date.data, 

            TotalDistance=form.total_distance.data 

        ) 

        db.session.add(trip) 

        db.session.commit() 

        flash('Trip created.') 

    trips = Trip.query.all() 

    return render_template('employee/manage_trips.html', trips=trips, form=form) 

@employee_blueprint.route('/assigned_alerts') 

@login_required 

@permission_required(2) 

def assigned_alerts(): 

    alerts = EmergencyDistressAlerts.query.filter_by(AssignedEmployeeID=current_user.AccountID).all() 

    return render_template('employee/assigned_alerts.html', alerts=alerts) 

@employee_blueprint.route('/all_distress_trips') 

@login_required 

@permission_required(2) 

def all_distress_trips(): 

    alerts = EmergencyDistressAlerts.query.filter_by(Status='Active').all() 

    return render_template('employee/all_distress_trips.html', alerts=alerts) 

@employee_blueprint.route('/resolve_alert/<int:alert_id>', methods=['POST']) 

@login_required 

@permission_required(2) 

def resolve_alert(alert_id): 

    alert = EmergencyDistressAlerts.query.get_or_404(alert_id) 

    if alert.AssignedEmployeeID != current_user.AccountID: 

        flash('Unauthorized action.') 

        return redirect(url_for('employee.assigned_alerts')) 

    alert.Status = 'Resolved' 

    db.session.commit() 

    flash('Alert resolved.') 

    return redirect(url_for('employee.assigned_alerts')) 

@employee_blueprint.route('/assign_alert/<int:alert_id>', methods=['POST']) 

@login_required 

@permission_required(2) 

def assign_alert(alert_id): 

    alert = EmergencyDistressAlerts.query.get_or_404(alert_id) 

    alert.AssignedEmployeeID = current_user.AccountID 

    db.session.commit() 

    flash('Alert assigned to you.') 

    return redirect(url_for('employee.all_distress_trips')) 

@employee_blueprint.route('/view_site_details') 

@login_required 

@permission_required(2) 

def view_site_details(): 

    locations = LocationsOfInterest.query.all() 

    return render_template('employee/view_site_details.html', locations=locations) 

@employee_blueprint.route('/customer_reviews') 

@login_required 

@permission_required(2) 

def customer_reviews(): 

    reviews = CustomerFeedback.query.all() 

    return render_template('employee/customer_reviews.html', reviews=reviews) 
