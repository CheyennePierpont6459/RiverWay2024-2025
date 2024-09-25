import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your_secret_key_here')
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://username:password@localhost/ccc_emergency_map'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
