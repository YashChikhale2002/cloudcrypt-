import logging
from typing import Dict, Any, Optional, Tuple
from werkzeug.exceptions import Forbidden
import json
from datetime import datetime

logger = logging.getLogger(__name__)

class PolicyEnforcementPoint:
    """
    Policy Enforcement Point (PEP) that enforces access control decisions.
    Acts as a gateway for all resource access attempts.
    """
    
    def __init__(self, db_session, policy_decision_point, key_management_service):
        self.db_session = db_session
        self.pdp = policy_decision_point
        self.kms = key_management_service
    
    def enforce_access(self, user_id: int, data_id: int, action: str) -> Dict[str, Any]:
        """
        Enforce access control for a user requesting access to data.
        
        Args:
            user_id: ID of the user requesting access
            data_id: ID of the data being accessed
            action: Type of access being requested (e.g., 'read', 'write', 'delete')
            
        Returns:
            If access is granted, returns data access information.
            
        Raises:
            Forbidden: If access is denied
        """
        from models.data import Data, AccessLog
        from models.user import User
        
        # Get decision from PDP
        try:
            decision = self.pdp.evaluate_access(user_id, data_id, action)
            
            # If access is denied, raise exception
            if decision['decision'] != 'ALLOW':
                logger.warning(f"Access denied: {decision['reason']}")
                raise Forbidden(description=decision['reason'])
            
            # If access is allowed, log the access
            user = self.db_session.query(User).get(user_id)
            data = self.db_session.query(Data).get(data_id)
            
            if not user or not data:
                logger.error(f"User {user_id} or data {data_id} not found")
                raise Forbidden(description="User or data not found")
            
            access_log = AccessLog(
                data_id=data_id,
                user_id=user_id,
                action=action,
                success=True
            )
            self.db_session.add(access_log)
            self.db_session.commit()
            
            logger.info(f"Access granted: User {user.username} for {action} on {data.name}")
            
            return {
                'data_id': data_id,
                'name': data.name,
                'file_path': data.file_path,
                'action': action,
                'access_granted': True,
                'user': user.username
            }
        except Exception as e:
            # Make sure we roll back the session on any errors
            self.db_session.rollback()
            if isinstance(e, Forbidden):
                raise
            logger.error(f"Error enforcing access: {str(e)}")
            raise Forbidden(description="Error enforcing access control")
    
    def get_decryption_key(self, user_id: int, data_id: int) -> Optional[bytes]:
        """
        Get the decryption key for a user to access encrypted data.
        Only provided if the user has permission to access the data.
        
        Args:
            user_id: ID of the user requesting the key
            data_id: ID of the encrypted data
            
        Returns:
            Decryption key bytes if access is allowed, None otherwise
        """
        from models.data import Data
        from models.user import User
        from services.encryption import EncryptionService
        
        try:
            # Check if user has read access to the data
            try:
                self.enforce_access(user_id, data_id, 'read')
            except Forbidden:
                logger.warning(f"Key access denied for user {user_id}, data {data_id}")
                return None
            
            # Get data and user
            data = self.db_session.query(Data).get(data_id)
            user = self.db_session.query(User).get(user_id)
            
            if not data or not user:
                logger.warning(f"Data {data_id} or user {user_id} not found")
                return None
                
            if not data.encrypted or not data.encrypted_key:
                logger.warning(f"Data {data_id} is not encrypted or missing key")
                return None
            
            # If user is the owner, they can directly decrypt
            if data.owner_id == user_id:
                encryption_service = EncryptionService(None)  # Config not needed for this operation
                # Get the owner's private key
                private_key = self._get_user_private_key(user_id)
                if private_key:
                    try:
                        return encryption_service.decrypt_key(data.encrypted_key, private_key)
                    except Exception as e:
                        logger.error(f"Error decrypting key: {str(e)}")
                        return None
                else:
                    logger.warning(f"No private key found for user {user_id}")
                    return None
            
            # For non-owners with permission, the key needs to be re-encrypted for them
            # This is a simplified example - in a real system, this would be more complex
            # and involve key sharing and delegation mechanisms
            logger.warning(f"Key access for non-owner not implemented")
            return None
            
        except Exception as e:
            logger.error(f"Error getting decryption key: {str(e)}")
            self.db_session.rollback()
            return None
    
    def _get_user_private_key(self, user_id: int) -> Optional[bytes]:
        """Get a user's private key."""
        try:
            # Query directly to avoid ORM issues
            result = self.db_session.execute(
                "SELECT private_key FROM users WHERE id = :user_id",
                {"user_id": user_id}
            ).fetchone()
            
            if not result or not result[0]:
                logger.warning(f"No private key found for user {user_id}")
                return None
            
            private_key = result[0]
            return private_key.encode('utf-8')
        except Exception as e:
            logger.error(f"Error retrieving private key: {str(e)}")
            return None
    
    def decrypt_file(self, user_id: int, data_id: int) -> Tuple[bool, str]:
        """
        Decrypt a file for a user with proper permissions.
        
        Args:
            user_id: ID of the user requesting decryption
            data_id: ID of the encrypted data
            
        Returns:
            Tuple containing:
                - success: Whether decryption was successful
                - result: Path to decrypted file or error message
        """
        from models.data import Data
        from services.encryption import EncryptionService
        
        try:
            # Get decryption key
            key = self.get_decryption_key(user_id, data_id)
            if not key:
                return False, "Failed to obtain decryption key"
            
            # Get data details
            data = self.db_session.query(Data).get(data_id)
            if not data:
                return False, "Data not found"
            
            # Create encryption service
            encryption_service = EncryptionService(None)  # Config not needed for this operation
            
            try:
                # Decrypt file
                decrypted_path = encryption_service.decrypt_file(
                    data.file_path, 
                    key, 
                    data.iv, 
                    ""  # Tag would be stored in a real implementation
                )
                
                # Verify integrity if hash is available
                if data.content_hash:
                    if not encryption_service.verify_file_integrity(decrypted_path, data.content_hash):
                        logger.warning(f"Integrity check failed for {data_id}")
                        return False, "Integrity check failed"
                
                return True, decrypted_path
                
            except Exception as e:
                logger.error(f"Decryption error: {str(e)}")
                return False, f"Decryption failed: {str(e)}"
                
        except Exception as e:
            logger.error(f"Error in decrypt_file: {str(e)}")
            self.db_session.rollback()
            return False, f"Decryption process error: {str(e)}"

class PolicyDecisionPoint:
    """
    Policy Decision Point (PDP) for evaluating access control decisions.
    Evaluates whether a user has access to a resource based on policies and attributes.
    """
    
    def __init__(self, db_session):
        self.db_session = db_session
    
    def evaluate_access(self, user_id: int, data_id: int, action: str) -> Dict[str, Any]:
        """
        Evaluate whether a user has access to perform an action on data.
        
        Args:
            user_id: ID of the user requesting access
            data_id: ID of the data being accessed
            action: Type of access being requested (e.g., 'read', 'write', 'delete')
            
        Returns:
            Dictionary containing:
                - decision: 'ALLOW' or 'DENY'
                - reason: Explanation for the decision
                - policies_evaluated: List of policies that were evaluated
        """
        try:
            from models.user import User
            from models.data import Data
            from models.policy import Policy
            
            # Get user, data, and applicable policies
            user = self.db_session.query(User).get(user_id)
            data = self.db_session.query(Data).get(data_id)
            
            if not user or not data:
                return {
                    'decision': 'DENY',
                    'reason': 'User or data not found',
                    'policies_evaluated': []
                }
            
            # Get user attributes
            user_attributes = {attr.name: True for attr in user.attributes}
            
            # Check if user is the owner (owners always have access)
            if data.owner_id == user_id:
                return {
                    'decision': 'ALLOW',
                    'reason': 'User is the data owner',
                    'policies_evaluated': []
                }
            
            # Get applicable policies for the data
            policies = data.policies
            
            if not policies:
                # Log denial but don't save audit record (no policy to associate it with)
                self._log_decision_no_policy(user_id, data_id, action, 'DENY')
                return {
                    'decision': 'DENY',
                    'reason': 'No policies grant access',
                    'policies_evaluated': []
                }
            
            # Sort policies by priority (higher priority first)
            policies = sorted(policies, key=lambda p: p.priority, reverse=True)
            
            # Evaluate each policy
            policies_evaluated = []
            for policy in policies:
                if not policy.is_active:
                    continue
                    
                policy_result = self._evaluate_policy(policy, user_attributes, action)
                policies_evaluated.append({
                    'policy_id': policy.id,
                    'policy_name': policy.name,
                    'result': policy_result
                })
                
                if policy_result:
                    # Log access decision
                    self._log_decision(user_id, data_id, action, 'ALLOW', policy.id)
                    
                    return {
                        'decision': 'ALLOW',
                        'reason': f'Access granted by policy: {policy.name}',
                        'policies_evaluated': policies_evaluated
                    }
            
            # If no policy granted access
            self._log_decision_no_policy(user_id, data_id, action, 'DENY')
            
            return {
                'decision': 'DENY',
                'reason': 'No policy grants the requested access',
                'policies_evaluated': policies_evaluated
            }
        except Exception as e:
            logger.error(f"Error evaluating access: {str(e)}")
            self.db_session.rollback()
            return {
                'decision': 'DENY',
                'reason': f'Error evaluating access: {str(e)}',
                'policies_evaluated': []
            }
    
    def _evaluate_policy(self, policy, user_attributes: Dict[str, bool], action: str) -> bool:
        """
        Evaluate a single policy against user attributes and requested action.
        
        Args:
            policy: The policy to evaluate
            user_attributes: Dictionary of user attributes
            action: The action being requested
            
        Returns:
            True if policy grants access, False otherwise
        """
        # Get policy expression
        policy_expr = policy.policy_expression
        
        # Check if the policy applies to the requested action
        if 'actions' in policy_expr and action not in policy_expr['actions']:
            return False
        
        # Evaluate condition expression
        return self._evaluate_condition(policy_expr, user_attributes)
    
    def _evaluate_condition(self, condition, user_attributes: Dict[str, bool]) -> bool:
        """
        Recursively evaluate a policy condition.
        
        Args:
            condition: The condition to evaluate
            user_attributes: Dictionary of user attributes
            
        Returns:
            True if condition is satisfied, False otherwise
        """
        # Handle different condition types
        if condition.get('operation') == 'AND':
            # All subconditions must be true
            return all(self._evaluate_condition(subcond, user_attributes) 
                      for subcond in condition.get('conditions', []))
        
        elif condition.get('operation') == 'OR':
            # At least one subcondition must be true
            return any(self._evaluate_condition(subcond, user_attributes) 
                      for subcond in condition.get('conditions', []))
        
        elif condition.get('operation') == 'NOT':
            # Negate the result of the subcondition
            return not self._evaluate_condition(condition.get('condition'), user_attributes)
        
        else:
            # Simple attribute condition
            attribute = condition.get('attribute')
            value = condition.get('value')
            
            # Check if user has the required attribute
            return user_attributes.get(attribute, False)
    
    def _log_decision(self, user_id: int, data_id: int, action: str, 
                     decision: str, policy_id: Optional[int]):
        """Log the access control decision for auditing purposes."""
        if policy_id is None:
            # Don't create an audit log if there's no policy to associate it with
            logger.info(f"Access decision: {decision} for user {user_id} to data {data_id} - action {action} (no policy)")
            return
            
        try:
            from models.policy import PolicyAudit
            
            # Create audit log
            audit_log = PolicyAudit(
                policy_id=policy_id,
                user_id=user_id,
                action=f"Access:{action}",
                details=json.dumps({
                    'data_id': data_id,
                    'decision': decision,
                    'timestamp': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                })
            )
            
            self.db_session.add(audit_log)
            self.db_session.commit()
            
            # Also log to application log
            logger.info(f"Access decision: {decision} for user {user_id} to data {data_id} - action {action} (policy {policy_id})")
        except Exception as e:
            logger.error(f"Error logging access decision: {str(e)}")
            self.db_session.rollback()
    
    def _log_decision_no_policy(self, user_id: int, data_id: int, action: str, decision: str):
        """Log access decisions that don't have an associated policy."""
        try:
            # Just log to application log, don't create a database entry
            logger.info(f"Access decision: {decision} for user {user_id} to data {data_id} - action {action} (no policy)")
        except Exception as e:
            logger.error(f"Error logging access decision: {str(e)}")