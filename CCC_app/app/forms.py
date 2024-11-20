from flask_wtf import FlaskForm 

from wtforms import StringField, PasswordField, SubmitField, EmailField, IntegerField, SelectField, DecimalField, TextAreaField 

from wtforms.validators import DataRequired, Email, EqualTo, NumberRange 

class LoginForm(FlaskForm): 

    email = EmailField('Email', validators=[DataRequired(), Email()]) 

    password = PasswordField('Password', validators=[DataRequired()]) 

    submit = SubmitField('Login') 

class RegistrationForm(FlaskForm): 

    first_name = StringField('First Name', validators=[DataRequired()]) 

    last_name = StringField('Last Name', validators=[DataRequired()]) 

    username = StringField('Username', validators=[DataRequired()]) 

    email = EmailField('Email', validators=[DataRequired(), Email()]) 

    password = PasswordField('Password', validators=[DataRequired()]) 

    password2 = PasswordField( 

        'Repeat Password', validators=[DataRequired(), EqualTo('password')] 

    ) 

    submit = SubmitField('Register') 

class CreateAdminForm(FlaskForm): 

    first_name = StringField('First Name', validators=[DataRequired()]) 

    last_name = StringField('Last Name', validators=[DataRequired()]) 

    username = StringField('Username', validators=[DataRequired()]) 

    email = EmailField('Email', validators=[DataRequired(), Email()]) 

    account_type = SelectField('Account Type', choices=[('Admin', 'Admin'), ('Super Admin', 'Super Admin')], validators=[DataRequired()]) 

    permission_tier = SelectField('Permission Tier', choices=[('3', 'Admin'), ('4', 'Super Admin')], validators=[DataRequired()]) 

    password = PasswordField('Password', validators=[DataRequired()]) 

    password2 = PasswordField( 

        'Repeat Password', validators=[DataRequired(), EqualTo('password')] 

    ) 

    submit = SubmitField('Create Account') 

class TripForm(FlaskForm): 

    route_id = IntegerField('Route ID', validators=[DataRequired()]) 

    trip_type_id = IntegerField('Trip Type ID', validators=[DataRequired()]) 

    trip_date = StringField('Trip Date', validators=[DataRequired()]) 

    total_distance = DecimalField('Total Distance', validators=[DataRequired()]) 

    submit = SubmitField('Create Trip') 

class DistressAlertForm(FlaskForm): 

    latitude = DecimalField('Latitude', validators=[DataRequired()]) 

    longitude = DecimalField('Longitude', validators=[DataRequired()]) 

    severity_level = SelectField('Severity Level', choices=[('Low', 'Low'), ('Medium', 'Medium'), ('High', 'High'), ('Critical', 'Critical')], validators=[DataRequired()]) 

    submit = SubmitField('Submit Alert') 

class FeedbackForm(FlaskForm): 

    customer_trip_id = IntegerField('Customer Trip ID', validators=[DataRequired()]) 

    rating = IntegerField('Rating', validators=[DataRequired(), NumberRange(min=1, max=5)]) 

    feedback = TextAreaField('Feedback') 

    submit = SubmitField('Submit Review') 
