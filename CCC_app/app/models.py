# models.py
from flask_sqlalchemy import SQLAlchemy 

from flask_login import UserMixin, LoginManager 

from werkzeug.security import generate_password_hash, check_password_hash 

from datetime import datetime 

from sqlalchemy.dialects.mysql import INTEGER, VARCHAR, TEXT, ENUM, DECIMAL, TINYINT, TIMESTAMP, DATETIME 

from sqlalchemy import ForeignKey, UniqueConstraint, CheckConstraint 

db = SQLAlchemy() 

login_manager = LoginManager() 

# Permissions Model 

class Permissions(db.Model): 

    __tablename__ = 'Permissions' 

    PermissionID = db.Column(TINYINT(unsigned=True), primary_key=True) 

    PermissionName = db.Column(VARCHAR(100), unique=True, nullable=False) 

# Account Model 

class Account(UserMixin, db.Model): 

    __tablename__ = 'Account' 

    AccountID = db.Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True) 

    Username = db.Column(VARCHAR(100), unique=True, nullable=False) 

    PasswordHash = db.Column(VARCHAR(255), nullable=False) 

    Email = db.Column(VARCHAR(100), unique=True, nullable=False) 

    PhoneNumber = db.Column(VARCHAR(15)) 

    Address = db.Column(TEXT) 

    RegistrationDate = db.Column(TIMESTAMP, default=datetime.utcnow) 

    FirstName = db.Column(VARCHAR(100), nullable=False) 

    LastName = db.Column(VARCHAR(100), nullable=False) 

    AccountType = db.Column(ENUM('Customer', 'Employee', 'Admin', 'Super Admin'), nullable=False) 

    PermissionTier = db.Column(TINYINT(unsigned=True), ForeignKey('Permissions.PermissionID'), nullable=False, default=0) 

    # Relationships 

    customer = db.relationship('Customer', backref='account', uselist=False) 

    employee = db.relationship('Employee', backref='account', uselist=False) 

    def get_id(self): 

        return self.AccountID 

    def set_password(self, password): 

        self.PasswordHash = generate_password_hash(password) 

    def check_password(self, password): 

        return check_password_hash(self.PasswordHash, password) 

# Customer Model 

class Customer(db.Model): 

    __tablename__ = 'Customer' 

    CustomerID = db.Column(INTEGER(unsigned=True), ForeignKey('Account.AccountID'), primary_key=True) 

    EmergencyContactName = db.Column(VARCHAR(100)) 

    EmergencyContactPhone = db.Column(VARCHAR(15)) 

    # Relationships 

    trips = db.relationship('CustomerTrip', backref='customer', lazy=True) 

    feedbacks = db.relationship('CustomerFeedback', backref='customer', lazy=True) 

# Employee Model 

class Employee(db.Model): 

    __tablename__ = 'Employee' 

    EmployeeID = db.Column(INTEGER(unsigned=True), ForeignKey('Account.AccountID'), primary_key=True) 

    Position = db.Column(VARCHAR(100), nullable=False) 

    HireDate = db.Column(TIMESTAMP, default=datetime.utcnow) 

    Status = db.Column(VARCHAR(50), default='Available', nullable=False) 

    RoleUpdateRequired = db.Column(TINYINT, default=0) 

    # Relationships 

    assigned_alerts = db.relationship('EmergencyDistressAlerts', backref='assigned_employee', lazy=True) 

    reported_conditions = db.relationship('RouteConditionLog', backref='reported_by_employee', lazy=True) 

# LocationsOfInterest Model 

class LocationsOfInterest(db.Model): 

    __tablename__ = 'LocationsOfInterest' 

    LocationID = db.Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True) 

    Name = db.Column(VARCHAR(100), nullable=False) 

    Description = db.Column(TEXT) 

    Latitude = db.Column(DECIMAL(10, 7), nullable=False) 

    Longitude = db.Column(DECIMAL(10, 7), nullable=False) 

    Type = db.Column(VARCHAR(50)) 

    Elevation = db.Column(DECIMAL(8, 2)) 

    TerrainType = db.Column(VARCHAR(50)) 

    AccessibilityNotes = db.Column(TEXT) 

    LastUpdated = db.Column(TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow) 

    # Relationships 

    start_routes = db.relationship('Route', backref='start_location', foreign_keys='Route.StartLocationID', lazy=True) 

    end_routes = db.relationship('Route', backref='end_location', foreign_keys='Route.EndLocationID', lazy=True) 

    resources = db.relationship('EmergencyResource', backref='current_location', lazy=True) 

# Route Model 

class Route(db.Model): 

    __tablename__ = 'Route' 

    RouteID = db.Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True) 

    StartLocationID = db.Column(INTEGER(unsigned=True), ForeignKey('LocationsOfInterest.LocationID'), nullable=False) 

    EndLocationID = db.Column(INTEGER(unsigned=True), ForeignKey('LocationsOfInterest.LocationID'), nullable=False) 

    Distance = db.Column(DECIMAL(5, 2), nullable=False) 

    EstimatedTime = db.Column(DECIMAL(5, 2)) 

    DifficultyLevel = db.Column(VARCHAR(50)) 

    AgeRequirement = db.Column(INTEGER) 

    # Relationships 

    trips = db.relationship('Trip', backref='route', lazy=True) 

    condition_logs = db.relationship('RouteConditionLog', backref='route', lazy=True) 

    points_of_interest = db.relationship('PointsOfInterest', backref='route', lazy=True) 

# PointsOfInterest Model 

class PointsOfInterest(db.Model): 

    __tablename__ = 'PointsOfInterest' 

    POIID = db.Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True) 

    Name = db.Column(VARCHAR(100), nullable=False) 

    Description = db.Column(TEXT) 

    Latitude = db.Column(DECIMAL(10, 7), nullable=False) 

    Longitude = db.Column(DECIMAL(10, 7), nullable=False) 

    RouteID = db.Column(INTEGER(unsigned=True), ForeignKey('Route.RouteID'), nullable=False) 

    Type = db.Column(VARCHAR(50)) 

    # Relationships 

    geofences = db.relationship('Geofences', backref='poi', lazy=True) 

# Geofences Model 

class Geofences(db.Model): 

    __tablename__ = 'Geofences' 

    GeofenceID = db.Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True) 

    POIID = db.Column(INTEGER(unsigned=True), ForeignKey('PointsOfInterest.POIID'), nullable=False) 

    Radius = db.Column(DECIMAL(6, 2), nullable=False) 

    AlertType = db.Column(VARCHAR(50)) 

# TripType Model 

class TripType(db.Model): 

    __tablename__ = 'TripType' 

    TripTypeID = db.Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True) 

    TypeName = db.Column(VARCHAR(100), unique=True, nullable=False) 

    Description = db.Column(TEXT) 

    # Relationships 

    trips = db.relationship('Trip', backref='trip_type', lazy=True) 

# Trip Model 

class Trip(db.Model): 

    __tablename__ = 'Trip' 

    TripID = db.Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True) 

    RouteID = db.Column(INTEGER(unsigned=True), ForeignKey('Route.RouteID'), nullable=False) 

    TripTypeID = db.Column(INTEGER(unsigned=True), ForeignKey('TripType.TripTypeID'), nullable=False) 

    TripDate = db.Column(TIMESTAMP, default=datetime.utcnow) 

    TotalDistance = db.Column(DECIMAL(5, 2)) 

    # Relationships 

    customer_trips = db.relationship('CustomerTrip', backref='trip', lazy=True) 

    distress_alerts = db.relationship('EmergencyDistressAlerts', backref='trip', lazy=True) 

# CustomerTrip Model 

class CustomerTrip(db.Model): 

    __tablename__ = 'CustomerTrip' 

    CustomerTripID = db.Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True) 

    CustomerID = db.Column(INTEGER(unsigned=True), ForeignKey('Customer.CustomerID'), nullable=False) 

    TripID = db.Column(INTEGER(unsigned=True), ForeignKey('Trip.TripID'), nullable=False) 

    __table_args__ = (UniqueConstraint('CustomerID', 'TripID', name='_customer_trip_uc'),) 

    # Relationships 

    feedbacks = db.relationship('CustomerFeedback', backref='customer_trip', lazy=True) 

    alerts = db.relationship('EmergencyDistressAlerts', backref='customer_trip', lazy=True) 

# EmergencyDistressAlerts Model 

class EmergencyDistressAlerts(db.Model): 

    __tablename__ = 'EmergencyDistressAlerts' 

    AlertID = db.Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True) 

    CustomerTripID = db.Column(INTEGER(unsigned=True), ForeignKey('CustomerTrip.CustomerTripID'), nullable=False) 

    Latitude = db.Column(DECIMAL(10, 7), nullable=False) 

    Longitude = db.Column(DECIMAL(10, 7), nullable=False) 

    Timestamp = db.Column(TIMESTAMP, default=datetime.utcnow) 

    Status = db.Column(VARCHAR(50), nullable=False) 

    SeverityLevel = db.Column(ENUM('Low', 'Medium', 'High', 'Critical'), default='Medium', nullable=False) 

    ResponseTime = db.Column(DATETIME) 

    ResolutionTime = db.Column(DATETIME) 

    ResolutionNotes = db.Column(TEXT) 

    AssignedEmployeeID = db.Column(INTEGER(unsigned=True), ForeignKey('Employee.EmployeeID')) 

# CustomerFeedback Model 

class CustomerFeedback(db.Model): 

    __tablename__ = 'CustomerFeedback' 

    FeedbackID = db.Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True) 

    CustomerTripID = db.Column(INTEGER(unsigned=True), ForeignKey('CustomerTrip.CustomerTripID'), nullable=False) 

    Feedback = db.Column(TEXT) 

    Rating = db.Column(INTEGER) 

    Timestamp = db.Column(TIMESTAMP, default=datetime.utcnow) 

    __table_args__ = ( 

        CheckConstraint('Rating BETWEEN 1 AND 5', name='check_rating'), 

    ) 

# EmergencyDistressAssignmentQueue Model 

class EmergencyDistressAssignmentQueue(db.Model): 

    __tablename__ = 'EmergencyDistressAssignmentQueue' 

    QueueID = db.Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True) 

    AlertID = db.Column(INTEGER(unsigned=True), ForeignKey('EmergencyDistressAlerts.AlertID'), nullable=False) 

    CreatedAt = db.Column(TIMESTAMP, default=datetime.utcnow) 

    Processed = db.Column(TINYINT, default=0) 

# EmergencyResource Model 

class EmergencyResource(db.Model): 

    __tablename__ = 'EmergencyResource' 

    ResourceID = db.Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True) 

    ResourceName = db.Column(VARCHAR(100), nullable=False) 

    ResourceType = db.Column(ENUM('Vehicle', 'Equipment', 'Personnel'), nullable=False) 

    CurrentLocationID = db.Column(INTEGER(unsigned=True), ForeignKey('LocationsOfInterest.LocationID')) 

    Status = db.Column(ENUM('Available', 'In Use', 'Out of Service'), default='Available') 

    LastUpdated = db.Column(TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow) 

# EmergencyResponseTeam Model 

class EmergencyResponseTeam(db.Model): 

    __tablename__ = 'EmergencyResponseTeam' 

    TeamID = db.Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True) 

    TeamName = db.Column(VARCHAR(100), nullable=False) 

    LeadEmployeeID = db.Column(INTEGER(unsigned=True), ForeignKey('Employee.EmployeeID')) 

    # Relationships 

    members = db.relationship('EmergencyResponseTeamMember', backref='team', lazy=True) 

# EmergencyResponseTeamMember Model 

class EmergencyResponseTeamMember(db.Model): 

    __tablename__ = 'EmergencyResponseTeamMember' 

    TeamID = db.Column(INTEGER(unsigned=True), ForeignKey('EmergencyResponseTeam.TeamID'), primary_key=True) 

    EmployeeID = db.Column(INTEGER(unsigned=True), ForeignKey('Employee.EmployeeID'), primary_key=True) 

    Role = db.Column(VARCHAR(50)) 

# RouteConditionLog Model 

class RouteConditionLog(db.Model): 

    __tablename__ = 'RouteConditionLog' 

    LogID = db.Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True) 

    RouteID = db.Column(INTEGER(unsigned=True), ForeignKey('Route.RouteID'), nullable=False) 

    ConditionType = db.Column(ENUM('Normal', 'Caution', 'Danger', 'Closed'), nullable=False) 

    Description = db.Column(TEXT) 

    ReportedBy = db.Column(INTEGER(unsigned=True), ForeignKey('Employee.EmployeeID')) 

    ReportedAt = db.Column(TIMESTAMP, default=datetime.utcnow) 

    ResolvedAt = db.Column(TIMESTAMP) 

# EmergencyIncidentAnalysis Model 

class EmergencyIncidentAnalysis(db.Model): 

    __tablename__ = 'EmergencyIncidentAnalysis' 

    AnalysisID = db.Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True) 

    AlertID = db.Column(INTEGER(unsigned=True), ForeignKey('EmergencyDistressAlerts.AlertID'), nullable=False) 

    ResponseTime = db.Column(INTEGER)  # in minutes 

    ResolutionTime = db.Column(INTEGER)  # in minutes 

    SuccessFactors = db.Column(TEXT) 

    ImprovementAreas = db.Column(TEXT) 

    AnalyzedBy = db.Column(INTEGER(unsigned=True), ForeignKey('Employee.EmployeeID')) 

    AnalysisDate = db.Column(TIMESTAMP, default=datetime.utcnow) 

# ActivityLog Model 

class ActivityLog(db.Model): 

    __tablename__ = 'ActivityLog' 

    LogID = db.Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True) 

    ActivityType = db.Column(VARCHAR(100)) 

    TableName = db.Column(VARCHAR(100)) 

    RecordID = db.Column(VARCHAR(100)) 

    OperationType = db.Column(VARCHAR(10)) 

    Description = db.Column(TEXT) 

    Username = db.Column(VARCHAR(100)) 

    Timestamp = db.Column(TIMESTAMP, default=datetime.utcnow)
