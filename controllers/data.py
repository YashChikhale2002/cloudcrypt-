from flask import Blueprint, request, jsonify, send_file, render_template, flash, redirect, url_for, current_app, abort
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
import os
import uuid
import logging
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, BooleanField, SelectField, SelectMultipleField, DateTimeField, SubmitField
from wtforms.validators import DataRequired, Optional, Length
from flask_wtf.file import FileField, FileRequired, FileAllowed

logger = logging.getLogger(__name__)

# Create Blueprint
data_bp = Blueprint('data', __name__)

# Define form classes here
class FileUploadForm(FlaskForm):
    """Form for uploading files."""
    file = FileField('File', validators=[FileRequired()])
    name = StringField('Name (Optional)', validators=[Length(max=100)])
    description = TextAreaField('Description (Optional)', validators=[Length(max=500)])
    encrypt = BooleanField('Encrypt File', default=True)
    submit = SubmitField('Upload')

class ShareFileForm(FlaskForm):
    """Form for sharing a file with another user."""
    user_id = SelectField('Share with User', validators=[DataRequired()], coerce=int)
    permissions = SelectMultipleField('Permissions', choices=[
        ('read', 'Read'),
        ('write', 'Write'),
        ('delete', 'Delete')
    ], default=['read'])
    expiration = DateTimeField('Expiration (Optional)', validators=[Optional()], format='%Y-%m-%dT%H:%M')
    policy_id = SelectField('Apply Policy', validators=[Optional()], coerce=int, validate_choice=False)
    submit = SubmitField('Share File')

    def __init__(self, *args, **kwargs):
        super(ShareFileForm, self).__init__(*args, **kwargs)
        # Set default empty choice for policy_id
        self.policy_id.choices = []

class RemoveShareForm(FlaskForm):
    """Form for removing shared access to a file."""
    submit = SubmitField('Remove')

def init_data_controller(db_session, config, encryption_service, 
                         key_management_service, policy_enforcement_point):
    """Initialize data controller with dependencies."""
    
    @data_bp.route('/upload', methods=['GET', 'POST'])
    @login_required
    def upload():
        """Handle file upload and encryption."""
        from models.data import Data
        from models.policy import Policy
        
        # Create form instance
        form = FileUploadForm()
        
        if form.validate_on_submit():
            file = form.file.data
            
            # Check file size - FIXED: access config as dictionary instead of object
            if request.content_length and request.content_length > config['MAX_CONTENT_LENGTH']:
                flash(f'File too large (max {config["MAX_CONTENT_LENGTH"]/1024/1024}MB)', 'error')
                return redirect(request.url)
            
            # Get encryption preference
            encrypt = form.encrypt.data
            
            # Create upload directory if it doesn't exist
            os.makedirs(config['UPLOAD_FOLDER'], exist_ok=True)
            
            # Save file with a secure filename
            filename = secure_filename(file.filename)
            if form.name.data:
                display_name = form.name.data
            else:
                display_name = filename
                
            unique_filename = f"{uuid.uuid4()}_{filename}"
            file_path = os.path.join(config['UPLOAD_FOLDER'], unique_filename)
            file.save(file_path)
            
            # Set secure permissions
            os.chmod(file_path, 0o600)
            
            # Create data record
            data_record = Data(
                name=display_name,
                file_path=file_path,
                file_type=file.content_type,
                description=form.description.data,
                size=os.path.getsize(file_path),
                encrypted=encrypt,
                owner_id=current_user.id
            )
            
            # If encryption is requested
            if encrypt:
                try:
                    # Generate data key
                    key_id, data_key = key_management_service.generate_data_key()
                    
                    # Encrypt file
                    encryption_result = encryption_service.encrypt_file(file_path, data_key)
                    
                    # Update data record with encryption details
                    data_record.file_path = encryption_result['encrypted_file_path']
                    data_record.iv = encryption_result['iv']
                    data_record.content_hash = encryption_result['content_hash']
                    
                    # Encrypt data key with user's public key
                    user_public_key = current_user.public_key.encode('utf-8')
                    encrypted_key = encryption_service.encrypt_key(data_key, user_public_key)
                    data_record.encrypted_key = encrypted_key
                    
                    # Delete original file
                    os.unlink(file_path)
                    
                    logger.info(f"File encrypted: {filename}")
                    
                except Exception as e:
                    logger.error(f"Encryption failed: {str(e)}")
                    flash(f'Encryption failed: {str(e)}', 'error')
                    return redirect(request.url)
            
            # Save data record
            db_session.add(data_record)
            db_session.commit()
            
            # Get selected policies
            policy_ids = request.form.getlist('policies')
            
            if policy_ids:
                # Get policy objects
                policies = db_session.query(Policy).filter(Policy.id.in_(policy_ids)).all()
                
                # Associate policies with data
                data_record.policies = policies
                db_session.commit()
            
            flash(f'File uploaded successfully{"" if not encrypt else " and encrypted"}', 'success')
            return redirect(url_for('data.list_files'))
        
        # For GET requests, show upload form
        # Get available policies for selection
        from models.policy import Policy
        policies = db_session.query(Policy).filter_by(is_active=True).all()
        
        return render_template('upload.html', form=form, policies=policies)
    
    @data_bp.route('/files')
    @login_required
    def list_files():
        """List files owned by or accessible to the current user."""
        from models.data import Data
        from models.policy import Policy
        
        # Get files owned by the user
        owned_files = db_session.query(Data).filter_by(owner_id=current_user.id).all()
        
        # Get files accessible to the user based on policies
        # This is a simplified approach - in a real system, this would involve
        # querying the PDP for each file or using a more efficient mechanism
        accessible_files = []
        
        # Get all files not owned by the user
        other_files = db_session.query(Data).filter(
            Data.owner_id != current_user.id
        ).all()
        
        for file in other_files:
            try:
                # Check if user has read access
                policy_enforcement_point.enforce_access(
                    current_user.id, file.id, 'read'
                )
                accessible_files.append(file)
            except:
                # If access is denied, skip this file
                continue
        
        return render_template('files.html', 
                            owned_files=owned_files, 
                            accessible_files=accessible_files)
    
    @data_bp.route('/files/<int:file_id>')
    @login_required
    def file_details(file_id):
        """Show details for a specific file."""
        from models.data import Data
        
        # Get file
        file = db_session.query(Data).get(file_id)
        
        if not file:
            flash('File not found', 'error')
            return redirect(url_for('data.list_files'))
        
        # Check if user has access
        try:
            policy_enforcement_point.enforce_access(
                current_user.id, file.id, 'read'
            )
        except:
            flash('Access denied', 'error')
            return redirect(url_for('data.list_files'))
        
        return render_template('file_details.html', file=file)
    
    @data_bp.route('/files/<int:file_id>/download')
    @login_required
    def download_file(file_id):
        """Download a file."""
        from models.data import Data
        
        # Get file
        file = db_session.query(Data).get(file_id)
        
        if not file:
            flash('File not found', 'error')
            return redirect(url_for('data.list_files'))
        
        # Check if user has access
        try:
            policy_enforcement_point.enforce_access(
                current_user.id, file.id, 'read'
            )
        except:
            flash('Access denied', 'error')
            return redirect(url_for('data.list_files'))
        
        # If file is encrypted, decrypt it
        if file.encrypted:
            success, result = policy_enforcement_point.decrypt_file(
                current_user.id, file.id
            )
            
            if not success:
                flash(f'Decryption failed: {result}', 'error')
                return redirect(url_for('data.file_details', file_id=file.id))
            
            # Send decrypted file
            return send_file(
                result,
                as_attachment=True,
                download_name=file.name
            )
        
        # If file is not encrypted, just send it
        return send_file(
            file.file_path,
            as_attachment=True,
            download_name=file.name
        )
    
    @data_bp.route('/files/<int:file_id>/delete', methods=['POST'])
    @login_required
    def delete_file(file_id):
        """Delete a file."""
        from models.data import Data
        
        # Create a form for CSRF protection
        form = RemoveShareForm()
        
        if form.validate_on_submit():
            # Get file
            file = db_session.query(Data).get(file_id)
            
            if not file:
                flash('File not found', 'error')
                return redirect(url_for('data.list_files'))
            
            # Only owner can delete
            if file.owner_id != current_user.id:
                flash('Only the owner can delete a file', 'error')
                return redirect(url_for('data.file_details', file_id=file.id))
            
            # Delete file from disk
            try:
                os.unlink(file.file_path)
            except Exception as e:
                logger.error(f"Failed to delete file from disk: {str(e)}")
            
            # Delete from database
            db_session.delete(file)
            db_session.commit()
            
            flash('File deleted', 'success')
            return redirect(url_for('data.list_files'))
        else:
            flash('CSRF validation failed', 'error')
            return redirect(url_for('data.file_details', file_id=file_id))
    
    @data_bp.route('/files/<int:file_id>/share', methods=['GET', 'POST'])
    @login_required
    def share_file(file_id):
        """Share a file with another user."""
        from models.data import Data, FileShare
        from models.policy import Policy
        from models.user import User
        
        # Get the file
        file = db_session.query(Data).filter_by(id=file_id).first()
        
        if not file:
            flash('File not found', 'error')
            return redirect(url_for('data.list_files'))
        
        # Check if user is the owner
        if file.owner_id != current_user.id:
            flash('You can only share files you own.', 'error')
            return redirect(url_for('data.list_files'))
        
        # Get all users except current user
        users = db_session.query(User).filter(User.id != current_user.id).all()
        policies = db_session.query(Policy).filter_by(creator_id=current_user.id, is_active=True).all()
        
        # Create form
        form = ShareFileForm()
        form.user_id.choices = [(user.id, f"{user.username} ({user.email})") for user in users]
        form.policy_id.choices = [(0, '-- No Policy --')] + [(policy.id, policy.name) for policy in policies]
        
        # Get existing shares for this file
        shared_users = db_session.query(FileShare).filter_by(file_id=file_id).all()
        
        if form.validate_on_submit():
            try:
                # Check if already shared with this user
                existing_share = db_session.query(FileShare).filter_by(
                    file_id=file_id, user_id=form.user_id.data
                ).first()
                
                if existing_share:
                    flash('This file is already shared with this user.', 'warning')
                else:
                    # Create new share
                    permissions = ','.join(form.permissions.data) if form.permissions.data else 'read'
                    
                    # Handle the policy_id - convert to None if it's 0 or empty
                    policy_id = None
                    if form.policy_id.data and form.policy_id.data != 0:
                        policy_id = form.policy_id.data
                    
                    share = FileShare(
                        file_id=file_id,
                        user_id=form.user_id.data,
                        permissions=permissions,
                        expires_at=form.expiration.data,
                        policy_id=policy_id
                    )
                    
                    db_session.add(share)
                    db_session.commit()
                    
                    # Get user for notification
                    user = db_session.query(User).get(form.user_id.data)
                    
                    flash(f'File shared successfully with {user.username}.', 'success')
                    return redirect(url_for('data.share_file', file_id=file_id))
            except Exception as e:
                logger.error(f"Error sharing file: {str(e)}")
                flash(f'Error sharing file: {str(e)}', 'error')
                db_session.rollback()
        
        return render_template('share.html',
                         file=file,
                         form=form,
                         users=users,
                         policies=policies,
                         shared_users=shared_users)
    
    @data_bp.route('/remove-share/<int:share_id>', methods=['POST'])
    @login_required
    def remove_share(share_id):
        """Remove shared access to a file."""
        from models.data import FileShare, Data
        from models.user import User
        
        # Create form for CSRF protection
        form = RemoveShareForm()
        
        if form.validate_on_submit():
            share = db_session.query(FileShare).filter_by(id=share_id).first()
            
            if not share:
                flash('Share not found', 'error')
                return redirect(url_for('data.list_files'))
                
            file = db_session.query(Data).filter_by(id=share.file_id).first()
            
            if not file:
                flash('File not found', 'error')
                return redirect(url_for('data.list_files'))
            
            # Check if user is the owner of the file
            if file.owner_id != current_user.id:
                flash('You can only manage sharing for files you own.', 'error')
                return redirect(url_for('data.list_files'))
            
            user = db_session.query(User).get(share.user_id)
            db_session.delete(share)
            db_session.commit()
            
            flash(f'File access removed for {user.username}.', 'success')
            return redirect(url_for('data.share_file', file_id=file.id))
        else:
            flash('CSRF validation failed', 'error')
            return redirect(url_for('data.list_files'))
    
    @data_bp.route('/files/<int:file_id>/audit')
    @login_required
    def file_audit(file_id):
        """View access audit logs for a file."""
        from models.data import Data, AccessLog
        
        # Get file
        file = db_session.query(Data).get(file_id)
        
        if not file:
            flash('File not found', 'error')
            return redirect(url_for('data.list_files'))
        
        # Only owner can view audit logs
        if file.owner_id != current_user.id:
            flash('Only the owner can view audit logs', 'error')
            return redirect(url_for('data.file_details', file_id=file.id))
        
        # Get audit logs
        logs = db_session.query(AccessLog).filter_by(
            data_id=file.id
        ).order_by(AccessLog.timestamp.desc()).all()
        
        return render_template('file_audit.html', file=file, logs=logs)
    
    @data_bp.route('/my-files')
    @login_required
    def my_files():
        """List files owned by the current user."""
        from models.data import Data
        
        # Get files owned by the user
        owned_files = db_session.query(Data).filter_by(owner_id=current_user.id).all()
        
        return render_template('my_files.html', files=owned_files)
    
    @data_bp.route('/shared-with-me')
    @login_required
    def shared_with_me():
        """List files shared with the current user."""
        from models.data import FileShare, Data
        
        # Get files shared with the user
        shared_files = db_session.query(Data).join(
            FileShare, FileShare.file_id == Data.id
        ).filter(
            FileShare.user_id == current_user.id
        ).all()
        
        return render_template('shared_with_me.html', files=shared_files)
    
    return data_bp