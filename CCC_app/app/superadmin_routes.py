from flask import Blueprint, render_template, redirect, url_for, flash, request 

from flask_login import login_required, current_user 

from decorators import permission_required 

from models import db, Account, LocationsOfInterest, Permissions 

from forms import CreateAdminForm 

superadmin_blueprint = Blueprint('superadmin', __name__, template_folder='templates/superadmin') 

@superadmin_blueprint.route('/') 

@login_required 

@permission_required(4) 

def index(): 

    return render_template('superadmin/index.html') 

@superadmin_blueprint.route('/create_user', methods=['GET', 'POST']) 

@login_required 

@permission_required(4) 

def create_user(): 

    form = CreateAdminForm() 

    if form.validate_on_submit(): 

        if Account.query.filter_by(Email=form.email.data).first(): 

            flash('Email already registered.') 

            return redirect(url_for('superadmin.create_user')) 

        if Account.query.filter_by(Username=form.username.data).first(): 

            flash('Username already taken.') 

            return redirect(url_for('superadmin.create_user')) 

        permission_tier = int(form.permission_tier.data) 

        if permission_tier not in [3, 4]: 

            flash('Invalid permission tier.') 

            return redirect(url_for('superadmin.create_user')) 

        user = Account( 

            Username=form.username.data, 

            Email=form.email.data, 

            FirstName=form.first_name.data, 

            LastName=form.last_name.data, 

            AccountType=form.account_type.data, 

            PermissionTier=permission_tier 

        ) 

        user.set_password(form.password.data) 

        db.session.add(user) 

        db.session.commit() 

        flash(f'{form.account_type.data} account created.') 

        return redirect(url_for('superadmin.manage_users')) 

    return render_template('superadmin/create_user.html', form=form) 

@superadmin_blueprint.route('/manage_users', methods=['GET', 'POST']) 

@login_required 

@permission_required(4) 

def manage_users(): 

    if request.method == 'POST': 

        data = request.form 

        if data.get('action') == 'delete': 

            user = Account.query.get_or_404(data['user_id']) 

            if user.PermissionTier >= current_user.PermissionTier: 

                flash('Cannot delete a user with equal or higher permission.') 

                return redirect(url_for('superadmin.manage_users')) 

            db.session.delete(user) 

            db.session.commit() 

            flash('User account deleted.') 

    users = Account.query.filter(Account.PermissionTier >= 3).all() 

    return render_template('superadmin/manage_users.html', users=users) 

@superadmin_blueprint.route('/create_site_details', methods=['GET', 'POST']) 

@login_required 

@permission_required(4) 

def create_site_details(): 

    if request.method == 'POST': 

        data = request.form 

        location = LocationsOfInterest( 

            Name=data['name'], 

            Description=data['description'], 

            Latitude=data['latitude'], 

            Longitude=data['longitude'] 

        ) 

        db.session.add(location) 

        db.session.commit() 

        flash('Site details created.') 

        return redirect(url_for('superadmin.manage_site_details')) 

    return render_template('superadmin/create_site_details.html') 

@superadmin_blueprint.route('/manage_site_details', methods=['GET', 'POST']) 

@login_required 

@permission_required(4) 

def manage_site_details(): 

    if request.method == 'POST': 

        data = request.form 

        location = LocationsOfInterest.query.get_or_404(data['location_id']) 

        location.Name = data['name'] 

        location.Description = data['description'] 

        db.session.commit() 

        flash('Site details updated.') 

    locations = LocationsOfInterest.query.all() 

    return render_template('superadmin/manage_site_details.html', locations=locations) 
