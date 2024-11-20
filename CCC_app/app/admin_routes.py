from flask import Blueprint, render_template, redirect, url_for, flash, request 

from flask_login import login_required, current_user 

from decorators import permission_required 

from models import db, Account, Employee, Trip, LocationsOfInterest, Permissions 

from forms import TripForm 

admin_blueprint = Blueprint('admin', __name__, template_folder='templates/admin') 

@admin_blueprint.route('/') 

@login_required 

@permission_required(3) 

def index(): 

    return render_template('admin/index.html') 

@admin_blueprint.route('/create_employee', methods=['GET', 'POST']) 

@login_required 

@permission_required(3) 

def create_employee(): 

    if request.method == 'POST': 

        data = request.form 

        if Account.query.filter_by(Email=data['email']).first(): 

            flash('Email already registered.') 

            return redirect(url_for('admin.create_employee')) 

        if Account.query.filter_by(Username=data['username']).first(): 

            flash('Username already taken.') 

            return redirect(url_for('admin.create_employee')) 

        user = Account( 

            Username=data['username'], 

            Email=data['email'], 

            FirstName=data['first_name'], 

            LastName=data['last_name'], 

            AccountType='Employee', 

            PermissionTier=2 

        ) 

        user.set_password(data['password']) 

        db.session.add(user) 

        db.session.commit() 

        # Create employee profile 

        employee = Employee(EmployeeID=user.AccountID, Position=data['position']) 

        db.session.add(employee) 

        db.session.commit() 

        flash('Employee account created.') 

        return redirect(url_for('admin.index')) 

    return render_template('admin/create_employee.html') 

@admin_blueprint.route('/view_trips') 

@login_required 

@permission_required(3) 

def view_trips(): 

    trips = Trip.query.all() 

    return render_template('admin/view_trips.html', trips=trips) 

@admin_blueprint.route('/view_site_details', methods=['GET', 'POST']) 

@login_required 

@permission_required(3) 

def view_site_details(): 

    if request.method == 'POST': 

        data = request.form 

        location = LocationsOfInterest.query.get_or_404(data['location_id']) 

        location.Name = data['name'] 

        location.Description = data['description'] 

        db.session.commit() 

        flash('Site details updated.') 

    locations = LocationsOfInterest.query.all() 

    return render_template('admin/view_site_details.html', locations=locations) 

@admin_blueprint.route('/override_assignments') 

@login_required 

@permission_required(3) 

def override_assignments(): 

    # Logic to override emergency team assignments 

    flash('Override assignments feature not implemented yet.') 

    return redirect(url_for('admin.index')) 
