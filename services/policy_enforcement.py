import logging
from typing import Dict, Any, Optional, Tuple
from werkzeug.exceptions import Forbidden

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
        decision = self.pdp.evaluate_access(user_id, data_id, action)
        
        # If access is denied, raise exception
        if decision['decision'] != 'ALLOW':
            logger.warning(f"Access denied: {decision['reason']}")
            raise Forbidden(description=decision['reason'])
        
        # If access is allowed, log the access
        user = self.db_session.query(User).get(user_id)
        data = self.db_session.query(Data).get(data_id)
        
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
        
        # Check if user has read access to the data
        try:
            self.enforce_access(user_id, data_id, 'read')
        except Forbidden:
            logger.warning(f"Key access denied for user {user_id}, data {data_id}")
            return None
        
        # Get data and user
        data = self.db_session.query(Data).get(data_id)
        user = self.db_session.query(User).get(user_id)
        
        if not data.encrypted or not data.encrypted_key:
            logger.warning(f"Data {data_id} is not encrypted or missing key")
            return None
        
        # If user is the owner, they can directly decrypt
        if data.owner_id == user_id:
            encryption_service = EncryptionService(None)  # Config not needed for this operation
            # Assuming the owner's private key is available in the session or securely accessible
            private_key = self._get_user_private_key(user_id)
            if private_key:
                try:
                    return encryption_service.decrypt_key(data.encrypted_key, private_key)
                except Exception as e:
                    logger.error(f"Error decrypting key: {str(e)}")
                    return None
        
        # For non-owners with permission, the key needs to be re-encrypted for them
        # This is a simplified example - in a real system, this would be more complex
        # and involve key sharing and delegation mechanisms
        logger.warning(f"Key access for non-owner not implemented")
        return None
    
    def _get_user_private_key(self, user_id: int) -> Optional[bytes]:
        """
        Get a user's private key (this is a stub - in a real system, 
        private keys would be securely stored or provided by the user).
        
        Args:
            user_id: ID of the user
            
        Returns:
            User's private key bytes if available, None otherwise
        """
        # In a real system, this would be handled differently
        # Private keys might be:
        # 1. Stored encrypted and protected by user's password
        # 2. Stored in a secure hardware module
        # 3. Provided by the user during the session
        
        # This is just a placeholder
        logger.warning("Private key retrieval is a stub - not implemented securely")
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
        
        # Get decryption key
        key = self.get_decryption_key(user_id, data_id)
        if not key:
            return False, "Failed to obtain decryption key"
        
        # Get data details
        data = self.db_session.query(Data).get(data_id)
        
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