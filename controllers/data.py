from flask import Blueprint, request, jsonify, send_file, render_template, flash, redirect, url_for
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
import os
import uuid
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Create Blueprint
data_bp = Blueprint('data', __name__)

def init_data_controller(db_session, config, encryption_service, 
                         key_management_service, policy_enforcement_point):
    """Initialize data controller with dependencies."""
    
    @data_bp.route('/upload', methods=['GET', 'POST'])
    @login_required
    def upload():
        """Handle file upload and encryption."""
        from models.data import Data
        from models.policy import Policy
        
        if request.method == 'POST':
            # Check if file part exists
            if 'file' not in request.files:
                flash('No file part', 'error')
                return redirect(request.url)
            
            file = request.files['file']
            
            # Check if user selected a file
            if file.filename == '':
                flash('No file selected', 'error')
                return redirect(request.url)
            
            # Check file size
            if request.content_length > config.MAX_CONTENT_LENGTH:
                flash(f'File too large (max {config.MAX_CONTENT_LENGTH/1024/1024}MB)', 'error')
                return redirect(request.url)
            
            # Get encryption preference
            encrypt = request.form.get('encrypt', 'yes') == 'yes'
            
            # Create upload directory if it doesn't exist
            os.makedirs(config.UPLOAD_FOLDER, exist_ok=True)
            
            # Save file with a secure filename
            filename = secure_filename(file.filename)
            unique_filename = f"{uuid.uuid4()}_{filename}"
            file_path = os.path.join(config.UPLOAD_FOLDER, unique_filename)
            file.save(file_path)
            
            # Set secure permissions
            os.chmod(file_path, 0o600)
            
            # Create data record
            data_record = Data(
                name=filename,
                file_path=file_path,
                file_type=file.content_type,
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
        
        return render_template('upload.html', policies=policies)
    
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
    
    @data_bp.route('/files/<int:file_id>/share', methods=['GET', 'POST'])
    @login_required
    def share_file(file_id):
        """Share a file by applying policies."""
        from models.data import Data
        from models.policy import Policy
        
        # Get file
        file = db_session.query(Data).get(file_id)
        
        if not file:
            flash('File not found', 'error')
            return redirect(url_for('data.list_files'))
        
        # Only owner can share
        if file.owner_id != current_user.id:
            flash('Only the owner can share a file', 'error')
            return redirect(url_for('data.file_details', file_id=file.id))
        
        if request.method == 'POST':
            # Get selected policies
            policy_ids = request.form.getlist('policies')
            
            # Clear existing policies
            file.policies = []
            
            if policy_ids:
                # Get policy objects
                policies = db_session.query(Policy).filter(Policy.id.in_(policy_ids)).all()
                
                # Associate policies with data
                file.policies = policies
            
            db_session.commit()
            
            flash('Sharing settings updated', 'success')
            return redirect(url_for('data.file_details', file_id=file.id))
        
        # For GET requests, show share form
        # Get all available policies
        policies = db_session.query(Policy).filter_by(is_active=True).all()
        
        # Get currently applied policies
        current_policy_ids = [policy.id for policy in file.policies]
        
        return render_template('share.html', 
                           file=file, 
                           policies=policies, 
                           current_policy_ids=current_policy_ids)
    
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
    
    return data_bp