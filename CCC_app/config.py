import os 

class Config: 

    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your_default_secret_key' 

    MYSQL_HOST = os.environ.get('MYSQL_HOST') or 'localhost' 

    MYSQL_USER = os.environ.get('MYSQL_USER') or 'root' 

    MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD') or 'your_mysql_password' 

    MYSQL_DB = os.environ.get('MYSQL_DB') or 'ccc_emergency_map' 

    # Construct SQLALCHEMY_DATABASE_URI based on the above credentials 

    SQLALCHEMY_DATABASE_URI = ( 

        f'mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}/{MYSQL_DB}' 

    ) 

    SQLALCHEMY_TRACK_MODIFICATIONS = False 
