from flask import Blueprint, render_template, redirect, url_for, flash, request 

from flask_login import login_required, current_user 

from decorators import permission_required 

from models import db, Trip, CustomerTrip, EmergencyDistressAlerts, CustomerFeedback, LocationsOfInterest 

from forms import DistressAlertForm, FeedbackForm 

customer_blueprint = Blueprint('customer', __name__, template_folder='templates/customer') 

@customer_blueprint.route('/') 

@login_required 

@permission_required(1) 

def index(): 

    return render_template('customer/index.html') 

@customer_blueprint.route('/view_trips') 

@login_required 

@permission_required(1) 

def view_trips(): 

    trips = Trip.query.all() 

    return render_template('customer/view_trips.html', trips=trips) 

@customer_blueprint.route('/check_in/<int:trip_id>', methods=['GET', 'POST']) 

@login_required 

@permission_required(1) 

def check_in(trip_id): 

    if request.method == 'POST': 

        # Check-in logic 

        customer_trip = CustomerTrip(CustomerID=current_user.AccountID, TripID=trip_id) 

        db.session.add(customer_trip) 

        db.session.commit() 

        flash('Checked in successfully.') 

        return redirect(url_for('customer.view_trips')) 

    trip = Trip.query.get_or_404(trip_id) 

    return render_template('customer/check_in.html', trip=trip) 

@customer_blueprint.route('/create_distress', methods=['GET', 'POST']) 

@login_required 

@permission_required(1) 

def create_distress(): 

    form = DistressAlertForm() 

    if form.validate_on_submit(): 

        # Assuming customer is on a trip 

        customer_trip = CustomerTrip.query.filter_by(CustomerID=current_user.AccountID).order_by(CustomerTrip.CustomerTripID.desc()).first() 

        if not customer_trip: 

            flash('You are not checked into any trip.') 

            return redirect(url_for('customer.index')) 

        alert = EmergencyDistressAlerts( 

            CustomerTripID=customer_trip.CustomerTripID, 

            Latitude=form.latitude.data, 

            Longitude=form.longitude.data, 

            Status='Active', 

            SeverityLevel=form.severity_level.data 

        ) 

        db.session.add(alert) 

        db.session.commit() 

        flash('Distress alert created.') 

        return redirect(url_for('customer.index')) 

    return render_template('customer/create_distress.html', form=form) 

@customer_blueprint.route('/view_site_details') 

@login_required 

@permission_required(1) 

def view_site_details(): 

    locations = LocationsOfInterest.query.all() 

    return render_template('customer/view_site_details.html', locations=locations) 

@customer_blueprint.route('/leave_review', methods=['GET', 'POST']) 

@login_required 

@permission_required(1) 

def leave_review(): 

    form = FeedbackForm() 

    if form.validate_on_submit(): 

        feedback = CustomerFeedback( 

            CustomerTripID=form.customer_trip_id.data, 

            Feedback=form.feedback.data, 

            Rating=form.rating.data 

        ) 

        db.session.add(feedback) 

        db.session.commit() 

        flash('Review submitted.') 

        return redirect(url_for('customer.index')) 

    # Fetch customer trips 

    customer_trips = CustomerTrip.query.filter_by(CustomerID=current_user.AccountID).all() 

    return render_template('customer/leave_review.html', form=form, customer_trips=customer_trips) 
