import os
from urllib.parse import quote_plus
from dotenv import load_dotenv

# Explicitly load .env file from the project root (adjust the path if needed)
dotenv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
load_dotenv(dotenv_path)

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "defaultsecretkey")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Email configuration
    MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.getenv('MAIL_PORT', 587))
    # If MAIL_USE_SSL is true, force MAIL_USE_TLS to be false.
    MAIL_USE_SSL = os.getenv('MAIL_USE_SSL', 'false').lower() == 'true'
    MAIL_USE_TLS = (not MAIL_USE_SSL) and (os.getenv('MAIL_USE_TLS', 'true').lower() == 'true')
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    # If MAIL_DEFAULT_SENDER is not explicitly set, fall back to MAIL_USERNAME.
    MAIL_DEFAULT_SENDER = (os.getenv('MAIL_USERNAME'), os.getenv('MAIL_USERNAME'))
    ROOT_PASSWORD = os.getenv('ROOT_PASSWORD')

    @classmethod
    def init_app(cls, app):
        pass

class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL") or (
        f"postgresql://{os.getenv('DB_USER', 'postgres')}:"
        f"{quote_plus(os.getenv('DB_PASSWORD', 'postgres'))}@"
        f"{os.getenv('DB_HOST', 'localhost')}/{os.getenv('DB_NAME', 'cave_country_canoes')}"
    )

class ProductionConfig(Config):
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL") or (
        f"postgresql://{os.getenv('DB_USER', 'postgres')}:"
        f"{quote_plus(os.getenv('DB_PASSWORD', 'postgres'))}@"
        f"{os.getenv('DB_HOST', 'db')}/{os.getenv('DB_NAME', 'cave_country_canoes')}"
    )

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
