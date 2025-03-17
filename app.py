from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, current_user
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from flask_talisman import Talisman

import logging
import os

from config import Config
from models import Base
from models.user import User
from models.data import Data
from models.policy import Policy

# Initialize services
from services.encryption import EncryptionService
from services.key_management import KeyManagementService
from services.policy_decision import PolicyDecisionPoint
from services.policy_enforcement import PolicyEnforcementPoint

# Initialize controllers
from controllers.auth import init_auth
from controllers.data import init_data_controller
from controllers.policy import init_policy_controller

def create_app(config=None):
    """Create and configure the Flask application."""
    app = Flask(__name__, 
            static_url_path='', 
            static_folder='static',
            template_folder='templates')
    
    # Load configuration
    if config is None:
        app.config.from_object(Config)
    else:
        app.config.from_object(config)
    
    # Configure Content Security Policy and initialize Talisman
    csp = {
        'default-src': "'self'",
        'style-src': ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com"],
        'font-src': ["'self'", "https://cdnjs.cloudflare.com"],
        'img-src': ["'self'", "data:"],
        'script-src': ["'self'", "'unsafe-inline'"]
    }
    
    Talisman(app, 
             content_security_policy=csp,
             content_security_policy_nonce_in=['script-src'],
             force_https=False)  # Set to True in production
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler("crypt_plus.log"),
            logging.StreamHandler()
        ]
    )
    
    # Create database engine and session
    engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])
    session_factory = sessionmaker(bind=engine)
    db_session = scoped_session(session_factory)
    
    # Create all tables in one go using the shared Base
    Base.metadata.create_all(engine)
    
    # Ensure upload directory exists
    os.makedirs(app.config.get('UPLOAD_FOLDER', 'uploads'), exist_ok=True)
    
    # Initialize services with explicit config parameters
    encryption_config = {
        'ENCRYPTION_KEY_SIZE': app.config.get('ENCRYPTION_KEY_SIZE', 256),
        'RSA_KEY_SIZE': app.config.get('RSA_KEY_SIZE', 2048)
    }
    encryption_service = EncryptionService(encryption_config)
    
    key_management_service = KeyManagementService(app.config, db_session)
    policy_decision_point = PolicyDecisionPoint(db_session)
    policy_enforcement_point = PolicyEnforcementPoint(
        db_session, policy_decision_point, key_management_service
    )
    
    # Initialize login manager
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'info'
    login_manager.init_app(app)
    
    @login_manager.user_loader
    def load_user(user_id):
        return db_session.query(User).get(int(user_id))
    
    # Register blueprints
    auth = init_auth(db_session, encryption_service)
    app.register_blueprint(auth, url_prefix='/auth')
    
    data_bp = init_data_controller(
        db_session, app.config, encryption_service, 
        key_management_service, policy_enforcement_point
    )
    app.register_blueprint(data_bp, url_prefix='/data')
    
    policy_bp = init_policy_controller(db_session)
    app.register_blueprint(policy_bp, url_prefix='/policy')
    
    # Main routes
    @app.route('/')
    def index():
        """Landing page."""
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        return render_template('index.html')
    
    @app.route('/dashboard')
    def dashboard():
        """User dashboard."""
        if not current_user.is_authenticated:
            return redirect(url_for('auth.login'))
        
        # Import models here to avoid circular imports
        from models.data import Data, AccessLog
        from models.policy import Policy
        
        # Get user's data
        user_files = db_session.query(Data).filter_by(
            owner_id=current_user.id
        ).order_by(Data.created_at.desc()).limit(5).all()
        
        # Get user's policies
        user_policies = db_session.query(Policy).filter_by(
            creator_id=current_user.id
        ).order_by(Policy.created_at.desc()).limit(5).all()
        
        # Get recent activity
        access_logs = db_session.query(AccessLog).filter_by(
            user_id=current_user.id
        ).order_by(AccessLog.timestamp.desc()).limit(10).all()
        
        return render_template('dashboard.html', 
                           user_files=user_files,
                           user_policies=user_policies,
                           access_logs=access_logs)
    
    @app.route('/about')
    def about():
        """About page with information about Crypt+."""
        return render_template('about.html')
    
    @app.route('/admin')
    def admin_dashboard():
        """Admin dashboard."""
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Access denied', 'error')
            return redirect(url_for('dashboard'))
        
        # Import models
        from models.user import User
        from models.data import Data
        from models.policy import Policy, PolicyAudit
        
        # Get user statistics
        total_users = db_session.query(User).count()
        active_users = db_session.query(User).filter_by(is_active=True).count()
        
        # Get data statistics
        total_files = db_session.query(Data).count()
        encrypted_files = db_session.query(Data).filter_by(encrypted=True).count()
        
        # Get policy statistics
        total_policies = db_session.query(Policy).count()
        active_policies = db_session.query(Policy).filter_by(is_active=True).count()
        
        # Get recent audit logs
        recent_audits = db_session.query(PolicyAudit).order_by(
            PolicyAudit.timestamp.desc()
        ).limit(20).all()
        
        return render_template('admin_dashboard.html',
                           total_users=total_users,
                           active_users=active_users,
                           total_files=total_files,
                           encrypted_files=encrypted_files,
                           total_policies=total_policies,
                           active_policies=active_policies,
                           recent_audits=recent_audits)
    
    # Error handlers
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('errors/404.html'), 404
    
    @app.errorhandler(403)
    def forbidden(e):
        return render_template('errors/403.html'), 403
    
    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template('errors/500.html'), 500
    
    # Security headers middleware
    @app.after_request
    def add_security_headers(response):
        for header, value in app.config.get('SECURE_HEADERS', {}).items():
            response.headers[header] = value
        return response
    
    # Cleanup on app shutdown
    @app.teardown_appcontext
    def shutdown_session(exception=None):
        db_session.remove()
    
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)