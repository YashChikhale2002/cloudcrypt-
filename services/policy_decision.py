from typing import Dict, List, Any, Optional
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

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
        self._log_decision(user_id, data_id, action, 'DENY', None)
        
        return {
            'decision': 'DENY',
            'reason': 'No policy grants the requested access',
            'policies_evaluated': policies_evaluated
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
        from models.policy import PolicyAudit
        
        # Create audit log
        audit_log = PolicyAudit(
            policy_id=policy_id,
            user_id=user_id,
            action=f"Access:{action}",
            details=json.dumps({
                'data_id': data_id,
                'decision': decision,
                'timestamp': datetime.utcnow().isoformat()
            })
        )
        
        self.db_session.add(audit_log)
        self.db_session.commit()
        
        # Also log to application log
        logger.info(f"Access decision: {decision} for user {user_id} to data {data_id} - action {action}")