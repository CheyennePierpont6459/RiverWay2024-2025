# app.py
from flask import Flask, render_template, redirect, url_for, flash 

from config import Config 

from models import db, login_manager 

from flask_migrate import Migrate 

from customer_routes import customer_blueprint 

from employee_routes import employee_blueprint 

from admin_routes import admin_blueprint 

from superadmin_routes import superadmin_blueprint 

from forms import LoginForm, RegistrationForm 

from flask_login import login_user, logout_user, login_required, current_user 

app = Flask(__name__) 

app.config.from_object(Config) 

# Initialize extensions 

db.init_app(app) 

login_manager.init_app(app) 

migrate = Migrate(app, db) 

# Register Blueprints 

app.register_blueprint(customer_blueprint, url_prefix='/customer') 

app.register_blueprint(employee_blueprint, url_prefix='/employee') 

app.register_blueprint(admin_blueprint, url_prefix='/admin') 

app.register_blueprint(superadmin_blueprint, url_prefix='/superadmin') 

# User Loader 

@login_manager.user_loader 

def load_user(user_id): 

    from models import Account 

    return Account.query.get(int(user_id)) 

# Routes for authentication 

@app.route('/') 

def index(): 

    return render_template('index.html') 

@app.route('/login', methods=['GET', 'POST']) 

def login(): 

    from models import Account 

    form = LoginForm() 

    if form.validate_on_submit(): 

        user = Account.query.filter_by(Email=form.email.data).first() 

        if user and user.check_password(form.password.data): 

            login_user(user) 

            flash('Logged in successfully.') 

            return redirect(url_for('dashboard')) 

        else: 

            flash('Invalid email or password.') 

    return render_template('login.html', form=form) 

@app.route('/register', methods=['GET', 'POST']) 

def register(): 

    from models import Account, Customer 

    form = RegistrationForm() 

    if form.validate_on_submit(): 

        if Account.query.filter_by(Email=form.email.data).first(): 

            flash('Email already registered.') 

            return redirect(url_for('register')) 

        if Account.query.filter_by(Username=form.username.data).first(): 

            flash('Username already taken.') 

            return redirect(url_for('register')) 

        user = Account( 

            Username=form.username.data, 

            Email=form.email.data, 

            FirstName=form.first_name.data, 

            LastName=form.last_name.data, 

            AccountType='Customer', 

            PermissionTier=1 

        ) 

        user.set_password(form.password.data) 

        db.session.add(user) 

        db.session.commit() 

        # Create customer profile 

        customer = Customer(CustomerID=user.AccountID) 

        db.session.add(customer) 

        db.session.commit() 

        flash('Registration successful. Please log in.') 

        return redirect(url_for('login')) 

    return render_template('register.html', form=form) 

@app.route('/logout') 

@login_required 

def logout(): 

    logout_user() 

    flash('You have been logged out.') 

    return redirect(url_for('index')) 

@app.route('/dashboard') 

@login_required 

def dashboard(): 

    if current_user.PermissionTier == 1: 

        return redirect(url_for('customer.index')) 

    elif current_user.PermissionTier == 2: 

        return redirect(url_for('employee.index')) 

    elif current_user.PermissionTier == 3: 

        return redirect(url_for('admin.index')) 

    elif current_user.PermissionTier == 4: 

        return redirect(url_for('superadmin.index')) 

    else: 

        flash('Unauthorized access.') 

        return redirect(url_for('logout')) 

if __name__ == '__main__': 

    app.run(debug=True) 
