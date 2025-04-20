from flask import Blueprint, request, jsonify, render_template, flash, redirect, url_for
from flask_login import login_required, current_user
import json
import logging
from datetime import datetime
from forms import PolicyForm, AttributeForm, RemoveShareForm

logger = logging.getLogger(__name__)

# Create Blueprint
policy_bp = Blueprint('policy', __name__)

def init_policy_controller(db_session):
    """Initialize policy controller with dependencies."""
    
    @policy_bp.route('/policies')
    @login_required
    def list_policies():
        """List all policies."""
        from models.policy import Policy
        
        # Regular users can only see their own policies and active policies
        if not current_user.is_admin:
            policies = db_session.query(Policy).filter(
                (Policy.creator_id == current_user.id) | (Policy.is_active == True)
            ).all()
        else:
            # Admins can see all policies
            policies = db_session.query(Policy).all()
        
        return render_template('policies.html', policies=policies)
    
    @policy_bp.route('/policies/create', methods=['GET', 'POST'])
    @login_required
    def create_policy():
        """Create a new policy."""
        from models.policy import Policy
        from models.user import Attribute
        
        # Create form
        form = PolicyForm()
        
        # For attribute selection checkboxes - needs to happen outside validate_on_submit
        attributes = db_session.query(Attribute).all()
        
        if form.validate_on_submit():
            # Get form data
            name = form.name.data
            description = form.description.data
            is_active = form.is_active.data
            priority = form.priority.data
            condition_type = form.condition_type.data
            
            # Check if policy with same name already exists
            existing_policy = db_session.query(Policy).filter_by(name=name).first()
            if existing_policy:
                flash('A policy with this name already exists', 'error')
                return redirect(request.url)
            
            # Get attribute conditions from form
            selected_attributes = request.form.getlist('attributes')
            
            # Build policy expression
            if len(selected_attributes) == 1:
                # Simple condition with one attribute
                policy_expression = {
                    'attribute': selected_attributes[0],
                    'value': True
                }
            else:
                # Compound condition with multiple attributes
                conditions = []
                for attr in selected_attributes:
                    conditions.append({
                        'attribute': attr,
                        'value': True
                    })
                
                policy_expression = {
                    'operation': condition_type,
                    'conditions': conditions,
                    'actions': ['read', 'write', 'delete']  # Default actions
                }
            
            # Create policy
            new_policy = Policy(
                name=name,
                description=description,
                is_active=is_active,
                priority=priority,
                policy_expression=policy_expression,
                creator_id=current_user.id
            )
            
            # Save policy
            db_session.add(new_policy)
            db_session.commit()
            
            # Log creation
            from models.policy import PolicyAudit
            audit = PolicyAudit(
                policy_id=new_policy.id,
                user_id=current_user.id,
                action='create',
                details=json.dumps({
                    'policy_name': name,
                    'timestamp': datetime.utcnow().isoformat()
                })
            )
            db_session.add(audit)
            db_session.commit()
            
            flash('Policy created successfully', 'success')
            return redirect(url_for('policy.list_policies'))
        
        # Get available attributes
        attributes = db_session.query(Attribute).all()
        
        return render_template('create_policy.html', form=form, attributes=attributes)
    
    @policy_bp.route('/policies/<int:policy_id>')
    @login_required
    def policy_details(policy_id):
        """Show details for a specific policy."""
        from models.policy import Policy
        
        # Get policy
        policy = db_session.query(Policy).get(policy_id)
        
        if not policy:
            flash('Policy not found', 'error')
            return redirect(url_for('policy.list_policies'))
        
        # Regular users can only view policies they created or active policies
        if not current_user.is_admin and policy.creator_id != current_user.id and not policy.is_active:
            flash('Access denied', 'error')
            return redirect(url_for('policy.list_policies'))
        
        return render_template('policy_details.html', policy=policy)
    
    @policy_bp.route('/policies/<int:policy_id>/edit', methods=['GET', 'POST'])
    @login_required
    def edit_policy(policy_id):
        """Edit an existing policy."""
        from models.policy import Policy, PolicyAudit
        from models.user import Attribute
        
        # Get policy
        policy = db_session.query(Policy).get(policy_id)
        
        if not policy:
            flash('Policy not found', 'error')
            return redirect(url_for('policy.list_policies'))
        
        # Only admins and policy creators can edit
        if not current_user.is_admin and policy.creator_id != current_user.id:
            flash('Only administrators and policy creators can edit policies', 'error')
            return redirect(url_for('policy.policy_details', policy_id=policy_id))
        
        # Create form
        form = PolicyForm()
        
        if form.validate_on_submit():
            # Get form data
            name = form.name.data
            description = form.description.data
            is_active = form.is_active.data
            priority = form.priority.data
            condition_type = form.condition_type.data
            
            # Check if policy with same name already exists (excluding current policy)
            existing_policy = db_session.query(Policy).filter(
                Policy.name == name,
                Policy.id != policy_id
            ).first()
            
            if existing_policy:
                flash('A policy with this name already exists', 'error')
                return redirect(request.url)
            
            # Get attribute conditions
            selected_attributes = request.form.getlist('attributes')
            
            # Build policy expression
            if len(selected_attributes) == 1:
                # Simple condition with one attribute
                policy_expression = {
                    'attribute': selected_attributes[0],
                    'value': True
                }
            else:
                # Compound condition with multiple attributes
                conditions = []
                for attr in selected_attributes:
                    conditions.append({
                        'attribute': attr,
                        'value': True
                    })
                
                policy_expression = {
                    'operation': condition_type,
                    'conditions': conditions,
                    'actions': ['read', 'write', 'delete']  # Default actions
                }
            
            # Update policy
            policy.name = name
            policy.description = description
            policy.is_active = is_active
            policy.priority = priority
            policy.policy_expression = policy_expression
            policy.updated_at = datetime.utcnow()
            
            # Save changes
            db_session.commit()
            
            # Log update
            audit = PolicyAudit(
                policy_id=policy.id,
                user_id=current_user.id,
                action='update',
                details=json.dumps({
                    'policy_name': name,
                    'timestamp': datetime.utcnow().isoformat()
                })
            )
            db_session.add(audit)
            db_session.commit()
            
            flash('Policy updated successfully', 'success')
            return redirect(url_for('policy.policy_details', policy_id=policy_id))
        
        # For GET requests, prepopulate form fields
        if request.method == 'GET':
            form.name.data = policy.name
            form.description.data = policy.description
            form.is_active.data = policy.is_active
            form.priority.data = policy.priority
            
            # Set condition type
            if 'operation' in policy.policy_expression:
                form.condition_type.data = policy.policy_expression['operation']
        
        # Get available attributes
        attributes = db_session.query(Attribute).all()
        
        # Extract currently selected attributes from policy expression
        selected_attributes = []
        condition_type = 'OR'
        
        if 'operation' in policy.policy_expression:
            condition_type = policy.policy_expression['operation']
            for condition in policy.policy_expression.get('conditions', []):
                if 'attribute' in condition:
                    selected_attributes.append(condition['attribute'])
        elif 'attribute' in policy.policy_expression:
            selected_attributes.append(policy.policy_expression['attribute'])
        
        return render_template('edit_policy.html', 
                            form=form,
                            policy=policy, 
                            attributes=attributes,
                            selected_attributes=selected_attributes,
                            condition_type=condition_type)
    
    @policy_bp.route('/policies/<int:policy_id>/toggle', methods=['POST'])
    @login_required
    def toggle_policy(policy_id):
        """Toggle a policy's active status."""
        from models.policy import Policy, PolicyAudit
        
        # Create form for CSRF protection
        form = RemoveShareForm()
        
        if form.validate_on_submit():
            # Get policy
            policy = db_session.query(Policy).get(policy_id)
            
            if not policy:
                flash('Policy not found', 'error')
                return redirect(url_for('policy.list_policies'))
            
            # Check if user is authorized (creator or admin)
            if policy.creator_id != current_user.id and not current_user.is_admin:
                flash('You are not authorized to modify this policy', 'error')
                return redirect(url_for('policy.policy_details', policy_id=policy_id))
            
            # Toggle the active status
            policy.is_active = not policy.is_active
            
            # Add to audit log
            audit_log = PolicyAudit(
                policy_id=policy.id,
                user_id=current_user.id,
                action=f"Policy {'activated' if policy.is_active else 'deactivated'}",
                details=json.dumps({
                    'timestamp': datetime.utcnow().isoformat(),
                    'policy_name': policy.name
                })
            )
            
            db_session.add(audit_log)
            db_session.commit()
            
            flash(f"Policy '{policy.name}' has been {'activated' if policy.is_active else 'deactivated'}", 'success')
        else:
            flash('CSRF validation failed', 'error')
            
        return redirect(url_for('policy.policy_details', policy_id=policy_id))
    
    @policy_bp.route('/policies/<int:policy_id>/delete', methods=['POST'])
    @login_required
    def delete_policy(policy_id):
        """Delete a policy."""
        from models.policy import Policy, PolicyAudit
        
        # Create form for CSRF protection
        form = RemoveShareForm()
        
        if form.validate_on_submit():
            # Get policy
            policy = db_session.query(Policy).get(policy_id)
            
            if not policy:
                flash('Policy not found', 'error')
                return redirect(url_for('policy.list_policies'))
            
            # Only admins and policy creators can delete
            if not current_user.is_admin and policy.creator_id != current_user.id:
                flash('Only administrators and policy creators can delete policies', 'error')
                return redirect(url_for('policy.policy_details', policy_id=policy_id))
            
            # Log deletion
            audit = PolicyAudit(
                policy_id=policy.id,
                user_id=current_user.id,
                action='delete',
                details=json.dumps({
                    'policy_name': policy.name,
                    'timestamp': datetime.utcnow().isoformat()
                })
            )
            db_session.add(audit)
            
            # Delete policy
            db_session.delete(policy)
            db_session.commit()
            
            flash('Policy deleted', 'success')
        else:
            flash('CSRF validation failed', 'error')
            
        return redirect(url_for('policy.list_policies'))
    
    @policy_bp.route('/policies/<int:policy_id>/audit')
    @login_required
    def policy_audit(policy_id):
        """View audit logs for a policy."""
        from models.policy import Policy, PolicyAudit
        
        # Get policy
        policy = db_session.query(Policy).get(policy_id)
        
        if not policy:
            flash('Policy not found', 'error')
            return redirect(url_for('policy.list_policies'))
        
        # Only admins and policy creators can view audit logs
        if not current_user.is_admin and policy.creator_id != current_user.id:
            flash('Only administrators and policy creators can view audit logs', 'error')
            return redirect(url_for('policy.policy_details', policy_id=policy_id))
        
        # Get audit logs
        logs = db_session.query(PolicyAudit).filter_by(
            policy_id=policy.id
        ).order_by(PolicyAudit.timestamp.desc()).all()
        
        return render_template('policy_audit.html', policy=policy, logs=logs)
    
    @policy_bp.route('/attributes')
    @login_required
    def list_attributes():
        """List all available attributes."""
        from models.user import Attribute
        
        attributes = db_session.query(Attribute).all()
        
        return render_template('attributes.html', attributes=attributes)
    
    @policy_bp.route('/attributes/create', methods=['GET', 'POST'])
    @login_required
    def create_attribute():
        """Create a new attribute."""
        from models.user import Attribute
        
        # Only admins can create attributes
        if not current_user.is_admin:
            flash('Only administrators can create attributes', 'error')
            return redirect(url_for('policy.list_attributes'))
        
        # Create form
        form = AttributeForm()
        
        if form.validate_on_submit():
            # Get form data
            name = form.name.data
            description = form.description.data
            
            # Check if attribute already exists
            existing_attr = db_session.query(Attribute).filter_by(name=name).first()
            if existing_attr:
                flash('An attribute with this name already exists', 'error')
                return redirect(request.url)
            
            # Create attribute
            new_attr = Attribute(
                name=name,
                description=description
            )
            
            # Save attribute
            db_session.add(new_attr)
            db_session.commit()
            
            flash('Attribute created successfully', 'success')
            return redirect(url_for('policy.list_attributes'))
        
        return render_template('create_attribute.html', form=form)
    
    @policy_bp.route('/attributes/<int:attr_id>/delete', methods=['POST'])
    @login_required
    def delete_attribute(attr_id):
        """Delete an attribute."""
        from models.user import Attribute
        
        # Create form for CSRF protection
        form = RemoveShareForm()
        
        if form.validate_on_submit():
            # Only admins can delete attributes
            if not current_user.is_admin:
                flash('Only administrators can delete attributes', 'error')
                return redirect(url_for('policy.list_attributes'))
            
            # Get attribute
            attr = db_session.query(Attribute).get(attr_id)
            
            if not attr:
                flash('Attribute not found', 'error')
                return redirect(url_for('policy.list_attributes'))
            
            # Delete attribute
            db_session.delete(attr)
            db_session.commit()
            
            flash('Attribute deleted', 'success')
        else:
            flash('CSRF validation failed', 'error')
            
        return redirect(url_for('policy.list_attributes'))
    
    return policy_bp