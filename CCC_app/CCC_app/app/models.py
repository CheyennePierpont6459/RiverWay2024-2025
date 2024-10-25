# models.py
from extensions import db
from flask_login import UserMixin
from datetime import datetime

class Account(db.Model, UserMixin):
    __tablename__ = 'Account'

    AccountID = db.Column(db.Integer, primary_key=True)
    Username = db.Column(db.String(100), unique=True, nullable=False)
    PasswordHash = db.Column(db.String(255), nullable=False)
    Email = db.Column(db.String(100), unique=True, nullable=False)
    PhoneNumber = db.Column(db.String(15))
    Address = db.Column(db.Text)
    RegistrationDate = db.Column(db.DateTime, default=db.func.current_timestamp())
    FirstName = db.Column(db.String(100), nullable=False)
    LastName = db.Column(db.String(100), nullable=False)
    AccountType = db.Column(db.Enum('Customer', 'Employee', 'Admin', 'Super Admin'), nullable=False)
    PermissionTier = db.Column(db.Integer, default=1)

    def get_id(self):
        return str(self.AccountID)

    def check_password(self, password):
        from werkzeug.security import check_password_hash
        return check_password_hash(self.PasswordHash, password)

    @property
    def is_admin(self):
        return self.PermissionTier >= 3

    @property
    def is_super_admin(self):
        return self.PermissionTier >= 4

    @property
    def is_employee(self):
        return self.PermissionTier >= 2

class Customer(db.Model):
    __tablename__ = 'Customer'
    CustomerID = db.Column(db.Integer, db.ForeignKey('Account.AccountID'), primary_key=True)
    EmergencyContactName = db.Column(db.String(100))
    EmergencyContactPhone = db.Column(db.String(15))
    trips = db.relationship('CustomerTrip', backref='customer', lazy=True)

class Employee(db.Model):
    __tablename__ = 'Employee'
    EmployeeID = db.Column(db.Integer, db.ForeignKey('Account.AccountID'), primary_key=True)
    Position = db.Column(db.String(100), nullable=False)
    HireDate = db.Column(db.DateTime, default=db.func.current_timestamp())
    Status = db.Column(db.String(50), default='Available')
    RoleUpdateRequired = db.Column(db.Boolean, default=False)

class EmergencyDistressAlert(db.Model):
    __tablename__ = 'EmergencyDistressAlerts'
    AlertID = db.Column(db.Integer, primary_key=True)
    CustomerID = db.Column(db.Integer, db.ForeignKey('Customer.CustomerID'), nullable=False)
    Latitude = db.Column(db.Float, nullable=False)
    Longitude = db.Column(db.Float, nullable=False)
    Timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    Status = db.Column(db.String(50), default='Pending')
    SeverityLevel = db.Column(db.Enum('Low', 'Medium', 'High', 'Critical'), default='Medium')
    ResponseTime = db.Column(db.DateTime)
    ResolutionTime = db.Column(db.DateTime)
    ResolutionNotes = db.Column(db.Text)
    AssignedEmployeeID = db.Column(db.Integer, db.ForeignKey('Employee.EmployeeID'))

class PointsOfInterest(db.Model):
    __tablename__ = 'PointsOfInterest'
    POIID = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(100), nullable=False)
    Description = db.Column(db.Text)
    Latitude = db.Column(db.Float, nullable=False)
    Longitude = db.Column(db.Float, nullable=False)
    Type = db.Column(db.String(50))

class CustomerFeedback(db.Model):
    __tablename__ = 'CustomerFeedback'
    FeedbackID = db.Column(db.Integer, primary_key=True)
    CustomerID = db.Column(db.Integer, db.ForeignKey('Customer.CustomerID'), nullable=False)
    Feedback = db.Column(db.Text)
    Rating = db.Column(db.Integer)
    Timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

class Trip(db.Model):
    __tablename__ = 'Trip'
    TripID = db.Column(db.Integer, primary_key=True)
    RouteID = db.Column(db.Integer, db.ForeignKey('Route.RouteID'), nullable=False)
    TripDate = db.Column(db.DateTime, default=db.func.current_timestamp())
    TotalDistance = db.Column(db.Float)

class CustomerTrip(db.Model):
    __tablename__ = 'CustomerTrip'
    CustomerTripID = db.Column(db.Integer, primary_key=True)
    CustomerID = db.Column(db.Integer, db.ForeignKey('Customer.CustomerID'), nullable=False)
    TripID = db.Column(db.Integer, db.ForeignKey('Trip.TripID'), nullable=False)
    CheckedIn = db.Column(db.Boolean, default=False)

class Route(db.Model):
    __tablename__ = 'Route'
    RouteID = db.Column(db.Integer, primary_key=True)
    StartLocationID = db.Column(db.Integer)
    EndLocationID = db.Column(db.Integer)
    Distance = db.Column(db.Float, nullable=False)
    EstimatedTime = db.Column(db.Float)
    DifficultyLevel = db.Column(db.String(50))
    AgeRequirement = db.Column(db.Integer)
