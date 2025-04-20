from flask import Blueprint, request, jsonify, session, redirect, url_for, render_template, flash
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import logging
import re
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Length, ValidationError

logger = logging.getLogger(__name__)

# Create Blueprint
auth = Blueprint('auth', __name__)

# Define form classes for proper CSRF handling
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(), 
        Length(min=4, max=20, message="Username must be between 4 and 20 characters")
    ])
    
    email = StringField('Email', validators=[DataRequired()])
    
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long")
    ])
    
    password_confirm = PasswordField('Confirm Password', validators=[
        DataRequired(), 
        EqualTo('password', message="Passwords must match")
    ])
    
    submit = SubmitField('Register')
    
    def validate_email(self, field):
        """Custom email validator that doesn't require the email_validator package"""
        # Basic email validation using regex
        email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        if not email_pattern.match(field.data):
            raise ValidationError('Invalid email address')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long")
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(), 
        EqualTo('new_password', message="Passwords must match")
    ])
    submit = SubmitField('Change Password')

def init_auth(db_session, encryption_service):
    """Initialize authentication controller with dependencies."""
    
    @auth.route('/register', methods=['GET', 'POST'])
    def register():
        """Handle user registration."""
        from models.user import User
        
        # Redirect if already logged in
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        
        form = RegistrationForm()
        
        if form.validate_on_submit():
            # Get form data
            username = form.username.data
            email = form.email.data
            password = form.password.data
            
            # Check if user already exists
            existing_user = db_session.query(User).filter(
                (User.username == username) | (User.email == email)
            ).first()
            
            if existing_user:
                flash('Username or email already in use', 'error')
                return render_template('register.html', form=form)
            
            try:
                # Generate key pair for the user
                private_key, public_key = encryption_service.generate_key_pair()
                
                # Create new user
                new_user = User(
                    username=username,
                    email=email,
                    public_key=public_key.decode('utf-8')
                )
                new_user.set_password(password)
                
                # Store private key (in a real system, this would be handled differently)
                # Ideally, the private key would be encrypted with the user's password
                # and stored securely, or not stored at all (requiring the user to provide it)
                user_key_path = os.path.join(
                    os.path.dirname(os.path.abspath(__file__)), 
                    f'../secure_storage/user_keys/{username}.key'
                )
                os.makedirs(os.path.dirname(user_key_path), exist_ok=True)
                
                with open(user_key_path, 'wb') as f:
                    f.write(private_key)
                
                # Set secure permissions
                os.chmod(user_key_path, 0o600)
                
                # Save user to database
                db_session.add(new_user)
                db_session.commit()
                
                logger.info(f"New user registered: {username}")
                flash('Registration successful, please log in', 'success')
                return redirect(url_for('auth.login'))
            except Exception as e:
                logger.error(f"Error during registration: {str(e)}")
                flash('An error occurred during registration', 'error')
                db_session.rollback()
        
        return render_template('register.html', form=form)
    
    @auth.route('/login', methods=['GET', 'POST'])
    def login():
        """Handle user login."""
        from models.user import User
        
        # Redirect if already logged in
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        
        form = LoginForm()
        
        if form.validate_on_submit():
            # Get form data
            username = form.username.data
            password = form.password.data
            remember = form.remember.data
            
            # Find user
            user = db_session.query(User).filter_by(username=username).first()
            
            if not user or not user.check_password(password):
                flash('Invalid username or password', 'error')
                return render_template('login.html', form=form)
            
            # Check if user is active
            if not user.is_active:
                flash('Account is disabled, please contact administrator', 'error')
                return render_template('login.html', form=form)
            
            # Update last login time
            user.last_login = datetime.utcnow()
            db_session.commit()
            
            # Log in user
            login_user(user, remember=remember)
            
            # Record login for audit
            logger.info(f"User {username} logged in")
            
            # Redirect to requested page or dashboard
            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'):  # Ensure the next URL is relative
                return redirect(next_page)
            return redirect(url_for('dashboard'))
        
        return render_template('login.html', form=form)
    
    @auth.route('/logout')
    @login_required
    def logout():
        """Handle user logout."""
        username = current_user.username
        logout_user()
        
        # Record logout for audit
        logger.info(f"User {username} logged out")
        
        flash('You have been logged out', 'info')
        return redirect(url_for('auth.login'))
    
    @auth.route('/profile')
    @login_required
    def profile():
        """Display and edit user profile."""
        form = ChangePasswordForm()
        return render_template('profile.html', form=form)
    
    @auth.route('/change-password', methods=['POST'])
    @login_required
    def change_password():
        """Change user password."""
        form = ChangePasswordForm()
        
        if form.validate_on_submit():
            # Check current password
            if not current_user.check_password(form.current_password.data):
                flash('Current password is incorrect', 'error')
                return redirect(url_for('auth.profile'))
            
            # Update password
            current_user.set_password(form.new_password.data)
            db_session.commit()
            
            # Record password change for audit
            logger.info(f"User {current_user.username} changed password")
            
            flash('Password updated successfully', 'success')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f"{getattr(form, field).label.text}: {error}", 'error')
                    
        return redirect(url_for('auth.profile'))
    
    @auth.route('/manage-attributes', methods=['GET', 'POST'])
    @login_required
    def manage_attributes():
        """Manage user attributes."""
        from models.user import Attribute
        from forms import ManageAttributesForm  # Import the new form
        
        form = ManageAttributesForm()
        
        # Get all available attributes
        attributes = db_session.query(Attribute).all()
        
        # Set form choices
        form.attributes.choices = [(attr.id, attr.name) for attr in attributes]
        
        # Get user's current attributes
        user_attribute_ids = [attr.id for attr in current_user.attributes]
        
        # Pre-select the user's current attributes
        if request.method == 'GET':
            form.attributes.data = user_attribute_ids
        
        if form.validate_on_submit():
            # Get selected attributes
            attribute_ids = form.attributes.data
            
            # Get attribute objects
            selected_attributes = db_session.query(Attribute).filter(
                Attribute.id.in_(attribute_ids)
            ).all()
            
            # Update user attributes
            current_user.attributes = selected_attributes
            db_session.commit()
            
            flash('Attributes updated successfully', 'success')
            return redirect(url_for('auth.profile'))
        
        return render_template('manage_attributes.html', 
                        form=form,
                        attributes=attributes,
                        user_attribute_ids=user_attribute_ids)
    
    @auth.route('/admin/users')
    @login_required
    def admin_users():
        """Admin interface for managing users."""
        # Only admins can access
        if not current_user.is_admin:
            flash('Access denied', 'error')
            return redirect(url_for('dashboard'))
        
        # Get all users
        from models.user import User
        users = db_session.query(User).all()
        
        return render_template('admin_users.html', users=users)
    
    @auth.route('/admin/users/<int:user_id>/toggle-active', methods=['POST'])
    @login_required
    def toggle_user_active(user_id):
        """Enable or disable a user account."""
        # Only admins can access
        if not current_user.is_admin:
            flash('Access denied', 'error')
            return redirect(url_for('dashboard'))
        
        # Get user
        from models.user import User
        user = db_session.query(User).get(user_id)
        
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('auth.admin_users'))
        
        # Toggle active status
        user.is_active = not user.is_active
        db_session.commit()
        
        # Record action for audit
        action = 'enabled' if user.is_active else 'disabled'
        logger.info(f"Admin {current_user.username} {action} user {user.username}")
        
        flash(f'User {user.username} has been {action}', 'success')
        return redirect(url_for('auth.admin_users'))
    
    @auth.route('/admin/users/<int:user_id>/toggle-admin', methods=['POST'])
    @login_required
    def toggle_user_admin(user_id):
        """Grant or revoke admin privileges."""
        # Only admins can access
        if not current_user.is_admin:
            flash('Access denied', 'error')
            return redirect(url_for('dashboard'))
        
        # Get user
        from models.user import User
        user = db_session.query(User).get(user_id)
        
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('auth.admin_users'))
        
        # Prevent self-demotion
        if user.id == current_user.id:
            flash('You cannot change your own admin status', 'error')
            return redirect(url_for('auth.admin_users'))
        
        # Toggle admin status
        user.is_admin = not user.is_admin
        db_session.commit()
        
        # Record action for audit
        action = 'granted admin privileges to' if user.is_admin else 'revoked admin privileges from'
        logger.info(f"Admin {current_user.username} {action} user {user.username}")
        
        flash(f'Admin status for {user.username} has been updated', 'success')
        return redirect(url_for('auth.admin_users'))
    
    @auth.route('/admin/users/<int:user_id>/reset-password', methods=['POST'])
    @login_required
    def reset_user_password(user_id):
        """Reset a user's password to a temporary one."""
        # Only admins can access
        if not current_user.is_admin:
            flash('Access denied', 'error')
            return redirect(url_for('dashboard'))
        
        # Get user
        from models.user import User
        user = db_session.query(User).get(user_id)
        
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('auth.admin_users'))
        
        # Generate temporary password
        import secrets
        import string
        temp_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
        
        # Update user password
        user.set_password(temp_password)
        db_session.commit()
        
        # Record action for audit
        logger.info(f"Admin {current_user.username} reset password for user {user.username}")
        
        flash(f'Password for {user.username} has been reset to: {temp_password}', 'success')
        return redirect(url_for('auth.admin_users'))
    
    return auth