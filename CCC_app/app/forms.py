from flask_wtf import FlaskForm
from wtforms import (StringField, PasswordField, SubmitField, SelectField, BooleanField,
                     DecimalField, IntegerField, TextAreaField, DateField)
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, NumberRange
from .models import Account

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    password = PasswordField('Password', validators=[
        DataRequired(), EqualTo('confirm_password', message='Passwords must match')])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    account_type = SelectField('Account Type', choices=[('Customer', 'Customer')], validators=[DataRequired()])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = Account.query.filter_by(Username=username.data).first()
        if user:
            raise ValidationError('Username already exists.')

    def validate_email(self, email):
        user = Account.query.filter_by(Email=email.data).first()
        if user:
            raise ValidationError('Email already registered.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class EmployeeCreationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    position = StringField('Position', validators=[DataRequired()])
    permission_tier = SelectField('Permission Tier', choices=[
        (2, 'Employee'),
        (3, 'Admin'),
    ], coerce=int)
    submit = SubmitField('Create Employee')

    def validate_username(self, username):
        user = Account.query.filter_by(Username=username.data).first()
        if user:
            raise ValidationError('Username already exists.')

    def validate_email(self, email):
        user = Account.query.filter_by(Email=email.data).first()
        if user:
            raise ValidationError('Email already registered.')

class RouteForm(FlaskForm):
    start_location_id = SelectField('Start Location', coerce=int, validators=[DataRequired()])
    end_location_id = SelectField('End Location', coerce=int, validators=[DataRequired()])
    distance = DecimalField('Distance (km)', validators=[DataRequired(), NumberRange(min=0)])
    estimated_time = DecimalField('Estimated Time (hours)', validators=[DataRequired(), NumberRange(min=0)])
    difficulty_level = SelectField('Difficulty Level', choices=[('Easy', 'Easy'), ('Moderate', 'Moderate'), ('Hard', 'Hard')], validators=[DataRequired()])
    age_requirement = IntegerField('Age Requirement', validators=[NumberRange(min=0)])
    submit = SubmitField('Create Route')

class PointOfInterestForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    description = TextAreaField('Description')
    latitude = DecimalField('Latitude', validators=[DataRequired()])
    longitude = DecimalField('Longitude', validators=[DataRequired()])
    route_id = SelectField('Route', coerce=int, validators=[DataRequired()])
    type = StringField('Type')
    submit = SubmitField('Create Point of Interest')

class GeofenceForm(FlaskForm):
    poi_id = SelectField('Point of Interest', coerce=int, validators=[DataRequired()])
    radius = DecimalField('Radius (meters)', validators=[DataRequired(), NumberRange(min=0)])
    alert_type = StringField('Alert Type', validators=[DataRequired()])
    submit = SubmitField('Create Geofence')

class TripRequestForm(FlaskForm):
    route_id = SelectField('Route', coerce=int, validators=[DataRequired()])
    trip_type_id = SelectField('Trip Type', coerce=int, validators=[DataRequired()])
    trip_date = DateField('Trip Date', format='%Y-%m-%d', validators=[DataRequired()])
    submit = SubmitField('Request Trip')

class DistressAlertForm(FlaskForm):
    latitude = DecimalField('Latitude', validators=[DataRequired()])
    longitude = DecimalField('Longitude', validators=[DataRequired()])
    severity_level = SelectField('Severity Level', choices=[('Low', 'Low'), ('Medium', 'Medium'), ('High', 'High'), ('Critical', 'Critical')], validators=[DataRequired()])
    description = TextAreaField('Description')
    submit = SubmitField('Send Distress Alert')
