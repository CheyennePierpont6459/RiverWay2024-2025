import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'secret_key'
    MYSQL_HOST = 'localhost'
    MYSQL_USER = 'root'
    MYSQL_PASSWORD = 'Preston-2020'
    MYSQL_DB = 'ccc_emergency_map'
