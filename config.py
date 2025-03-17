import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-replace-in-production'
    
    # Database configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URI') or 'sqlite:///crypt_plus.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Encryption settings
    ENCRYPTION_KEY_SIZE = 256  # AES-256
    RSA_KEY_SIZE = 2048        # RSA key size
    
    # File upload settings
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max file size
    
    # Access control settings
    ACCESS_CONTROL_REFRESH_INTERVAL = 300  # 5 minutes
    
    # Security headers
    SECURE_HEADERS = {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'SAMEORIGIN',
        'X-XSS-Protection': '1; mode=block',
        'Content-Security-Policy': "default-src 'self'"
    }