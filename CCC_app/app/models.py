from . import db
from flask_login import UserMixin
from . import login_manager
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

class Permissions(db.Model):
    __tablename__ = 'Permissions'
    PermissionID = db.Column(db.Integer, primary_key=True)
    PermissionName = db.Column(db.String(100), unique=True, nullable=False)

class Account(db.Model, UserMixin):
    __tablename__ = 'Account'

    AccountID = db.Column(db.Integer, primary_key=True)
    Username = db.Column(db.String(100), unique=True, nullable=False)
    PasswordHash = db.Column(db.String(255), nullable=False)
    Email = db.Column(db.String(100), unique=True, nullable=False)
    PhoneNumber = db.Column(db.String(15))
    Address = db.Column(db.Text)
    RegistrationDate = db.Column(db.DateTime, default=datetime.utcnow)
    FirstName = db.Column(db.String(100), nullable=False)
    LastName = db.Column(db.String(100), nullable=False)
    AccountType = db.Column(db.Enum('Customer', 'Employee'), nullable=False)
    PermissionTier = db.Column(db.Integer, default=1)

    # Relationships
    customer = db.relationship('Customer', back_populates='account', uselist=False)
    employee = db.relationship('Employee', back_populates='account', uselist=False)

    def get_id(self):
        return str(self.AccountID)

    @property
    def is_admin(self):
        return self.PermissionTier >= 3

    @property
    def is_super_admin(self):
        return self.PermissionTier >= 4

    @property
    def is_employee(self):
        return self.PermissionTier >= 2

    def set_password(self, password):
        self.PasswordHash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.PasswordHash, password)

class Customer(db.Model):
    __tablename__ = 'Customer'
    CustomerID = db.Column(db.Integer, db.ForeignKey('Account.AccountID'), primary_key=True)
    EmergencyContactName = db.Column(db.String(100))
    EmergencyContactPhone = db.Column(db.String(15))

    account = db.relationship('Account', back_populates='customer')
    trips = db.relationship('CustomerTrip', back_populates='customer')

class Employee(db.Model):
    __tablename__ = 'Employee'
    EmployeeID = db.Column(db.Integer, db.ForeignKey('Account.AccountID'), primary_key=True)
    Position = db.Column(db.String(100), nullable=False)
    HireDate = db.Column(db.DateTime, default=datetime.utcnow)
    Status = db.Column(db.String(50), default='Available', nullable=False)
    RoleUpdateRequired = db.Column(db.Boolean, default=False)

    account = db.relationship('Account', back_populates='employee')
    distress_alerts = db.relationship('EmergencyDistressAlerts', back_populates='assigned_employee')
    route_condition_logs = db.relationship('RouteConditionLog', back_populates='reported_by_employee')
    incident_analyses = db.relationship('EmergencyIncidentAnalysis', back_populates='analyzed_by_employee')

class LocationsOfInterest(db.Model):
    __tablename__ = 'LocationsOfInterest'
    LocationID = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(100), nullable=False)
    Description = db.Column(db.Text)
    Latitude = db.Column(db.Numeric(10, 7), nullable=False)
    Longitude = db.Column(db.Numeric(10, 7), nullable=False)
    Type = db.Column(db.String(50))
    Elevation = db.Column(db.Numeric(8, 2))
    TerrainType = db.Column(db.String(50))
    AccessibilityNotes = db.Column(db.Text)
    LastUpdated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    routes_start = db.relationship('Route', back_populates='start_location', foreign_keys='Route.StartLocationID')
    routes_end = db.relationship('Route', back_populates='end_location', foreign_keys='Route.EndLocationID')
    emergency_resources = db.relationship('EmergencyResource', back_populates='current_location')

class Route(db.Model):
    __tablename__ = 'Route'
    RouteID = db.Column(db.Integer, primary_key=True)
    StartLocationID = db.Column(db.Integer, db.ForeignKey('LocationsOfInterest.LocationID'), nullable=False)
    EndLocationID = db.Column(db.Integer, db.ForeignKey('LocationsOfInterest.LocationID'), nullable=False)
    Distance = db.Column(db.Numeric(5, 2), nullable=False)
    EstimatedTime = db.Column(db.Numeric(5, 2))
    DifficultyLevel = db.Column(db.String(50))
    AgeRequirement = db.Column(db.Integer)

    start_location = db.relationship('LocationsOfInterest', back_populates='routes_start', foreign_keys=[StartLocationID])
    end_location = db.relationship('LocationsOfInterest', back_populates='routes_end', foreign_keys=[EndLocationID])
    trips = db.relationship('Trip', back_populates='route')
    route_condition_logs = db.relationship('RouteConditionLog', back_populates='route')
    points_of_interest = db.relationship('PointsOfInterest', back_populates='route')

class PointsOfInterest(db.Model):
    __tablename__ = 'PointsOfInterest'
    POIID = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(100), nullable=False)
    Description = db.Column(db.Text)
    Latitude = db.Column(db.Numeric(10, 7), nullable=False)
    Longitude = db.Column(db.Numeric(10, 7), nullable=False)
    RouteID = db.Column(db.Integer, db.ForeignKey('Route.RouteID'), nullable=False)
    Type = db.Column(db.String(50))

    route = db.relationship('Route', back_populates='points_of_interest')
    geofences = db.relationship('Geofences', back_populates='poi')

class Geofences(db.Model):
    __tablename__ = 'Geofences'
    GeofenceID = db.Column(db.Integer, primary_key=True)
    POIID = db.Column(db.Integer, db.ForeignKey('PointsOfInterest.POIID'), nullable=False)
    Radius = db.Column(db.Numeric(6, 2), nullable=False)
    AlertType = db.Column(db.String(50))

    poi = db.relationship('PointsOfInterest', back_populates='geofences')

class TripType(db.Model):
    __tablename__ = 'TripType'
    TripTypeID = db.Column(db.Integer, primary_key=True)
    TypeName = db.Column(db.String(100), unique=True, nullable=False)
    Description = db.Column(db.Text)

    trips = db.relationship('Trip', back_populates='trip_type')

class Trip(db.Model):
    __tablename__ = 'Trip'
    TripID = db.Column(db.Integer, primary_key=True)
    RouteID = db.Column(db.Integer, db.ForeignKey('Route.RouteID'), nullable=False)
    TripTypeID = db.Column(db.Integer, db.ForeignKey('TripType.TripTypeID'), nullable=False)
    TripDate = db.Column(db.DateTime, default=datetime.utcnow)
    TotalDistance = db.Column(db.Numeric(5, 2))

    route = db.relationship('Route', back_populates='trips')
    trip_type = db.relationship('TripType', back_populates='trips')
    customers = db.relationship('CustomerTrip', back_populates='trip')
    feedbacks = db.relationship('CustomerFeedback', back_populates='trip')

class CustomerTrip(db.Model):
    __tablename__ = 'CustomerTrip'
    CustomerTripID = db.Column(db.Integer, primary_key=True)
    CustomerID = db.Column(db.Integer, db.ForeignKey('Customer.CustomerID'), nullable=False)
    TripID = db.Column(db.Integer, db.ForeignKey('Trip.TripID'), nullable=False)

    customer = db.relationship('Customer', back_populates='trips')
    trip = db.relationship('Trip', back_populates='customers')
    distress_alerts = db.relationship('EmergencyDistressAlerts', back_populates='customer_trip')
    feedbacks = db.relationship('CustomerFeedback', back_populates='customer_trip')

class EmergencyDistressAlerts(db.Model):
    __tablename__ = 'EmergencyDistressAlerts'
    AlertID = db.Column(db.Integer, primary_key=True)
    CustomerTripID = db.Column(db.Integer, db.ForeignKey('CustomerTrip.CustomerTripID'), nullable=False)
    Latitude = db.Column(db.Numeric(10, 7), nullable=False)
    Longitude = db.Column(db.Numeric(10, 7), nullable=False)
    Timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    Status = db.Column(db.String(50), nullable=False)
    SeverityLevel = db.Column(db.Enum('Low', 'Medium', 'High', 'Critical'), default='Medium', nullable=False)
    ResponseTime = db.Column(db.DateTime)
    ResolutionTime = db.Column(db.DateTime)
    ResolutionNotes = db.Column(db.Text)
    AssignedEmployeeID = db.Column(db.Integer, db.ForeignKey('Employee.EmployeeID'))

    customer_trip = db.relationship('CustomerTrip', back_populates='distress_alerts')
    assigned_employee = db.relationship('Employee', back_populates='distress_alerts')
    incident_analysis = db.relationship('EmergencyIncidentAnalysis', back_populates='alert', uselist=False)

class CustomerFeedback(db.Model):
    __tablename__ = 'CustomerFeedback'
    FeedbackID = db.Column(db.Integer, primary_key=True)
    CustomerTripID = db.Column(db.Integer, db.ForeignKey('CustomerTrip.CustomerTripID'), nullable=False)
    Feedback = db.Column(db.Text)
    Rating = db.Column(db.Integer)
    Timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    customer_trip = db.relationship('CustomerTrip', back_populates='feedbacks')
    trip = db.relationship('Trip', back_populates='feedbacks')

class EmergencyDistressAssignmentQueue(db.Model):
    __tablename__ = 'EmergencyDistressAssignmentQueue'
    QueueID = db.Column(db.Integer, primary_key=True)
    AlertID = db.Column(db.Integer, db.ForeignKey('EmergencyDistressAlerts.AlertID'), nullable=False)
    CreatedAt = db.Column(db.DateTime, default=datetime.utcnow)
    Processed = db.Column(db.Boolean, default=False)

    alert = db.relationship('EmergencyDistressAlerts')

class EmergencyResource(db.Model):
    __tablename__ = 'EmergencyResource'
    ResourceID = db.Column(db.Integer, primary_key=True)
    ResourceName = db.Column(db.String(100), nullable=False)
    ResourceType = db.Column(db.Enum('Vehicle', 'Equipment', 'Personnel'), nullable=False)
    CurrentLocationID = db.Column(db.Integer, db.ForeignKey('LocationsOfInterest.LocationID'))
    Status = db.Column(db.Enum('Available', 'In Use', 'Out of Service'), default='Available')
    LastUpdated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    current_location = db.relationship('LocationsOfInterest', back_populates='emergency_resources')

class EmergencyResponseTeam(db.Model):
    __tablename__ = 'EmergencyResponseTeam'
    TeamID = db.Column(db.Integer, primary_key=True)
    TeamName = db.Column(db.String(100), nullable=False)
    LeadEmployeeID = db.Column(db.Integer, db.ForeignKey('Employee.EmployeeID'))

    lead_employee = db.relationship('Employee')
    members = db.relationship('EmergencyResponseTeamMember', back_populates='team')

class EmergencyResponseTeamMember(db.Model):
    __tablename__ = 'EmergencyResponseTeamMember'
    TeamID = db.Column(db.Integer, db.ForeignKey('EmergencyResponseTeam.TeamID'), primary_key=True)
    EmployeeID = db.Column(db.Integer, db.ForeignKey('Employee.EmployeeID'), primary_key=True)
    Role = db.Column(db.String(50))

    team = db.relationship('EmergencyResponseTeam', back_populates='members')
    employee = db.relationship('Employee')

class RouteConditionLog(db.Model):
    __tablename__ = 'RouteConditionLog'
    LogID = db.Column(db.Integer, primary_key=True)
    RouteID = db.Column(db.Integer, db.ForeignKey('Route.RouteID'), nullable=False)
    ConditionType = db.Column(db.Enum('Normal', 'Caution', 'Danger', 'Closed'), nullable=False)
    Description = db.Column(db.Text)
    ReportedBy = db.Column(db.Integer, db.ForeignKey('Employee.EmployeeID'))
    ReportedAt = db.Column(db.DateTime, default=datetime.utcnow)
    ResolvedAt = db.Column(db.DateTime)

    route = db.relationship('Route', back_populates='route_condition_logs')
    reported_by_employee = db.relationship('Employee', back_populates='route_condition_logs')

class EmergencyIncidentAnalysis(db.Model):
    __tablename__ = 'EmergencyIncidentAnalysis'
    AnalysisID = db.Column(db.Integer, primary_key=True)
    AlertID = db.Column(db.Integer, db.ForeignKey('EmergencyDistressAlerts.AlertID'), nullable=False)
    ResponseTime = db.Column(db.Integer)  # in minutes
    ResolutionTime = db.Column(db.Integer)  # in minutes
    SuccessFactors = db.Column(db.Text)
    ImprovementAreas = db.Column(db.Text)
    AnalyzedBy = db.Column(db.Integer, db.ForeignKey('Employee.EmployeeID'))
    AnalysisDate = db.Column(db.DateTime, default=datetime.utcnow)

    alert = db.relationship('EmergencyDistressAlerts', back_populates='incident_analysis')
    analyzed_by_employee = db.relationship('Employee', back_populates='incident_analyses')

class ActivityLog(db.Model):
    __tablename__ = 'ActivityLog'
    LogID = db.Column(db.Integer, primary_key=True)
    ActivityType = db.Column(db.String(100))
    TableName = db.Column(db.String(100))
    RecordID = db.Column(db.Integer)
    OperationType = db.Column(db.String(10))
    Description = db.Column(db.Text)
    Username = db.Column(db.String(100))
    Timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return Account.query.get(int(user_id))
