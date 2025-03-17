import os
import json
import hashlib
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from Crypto.PublicKey import RSA
from cryptography.fernet import Fernet
from base64 import b64encode, b64decode

class KeyManagementService:
    """
    Key Management Service (KMS) for managing encryption keys.
    Implements secure key storage, rotation, and distribution.
    """
    
    def __init__(self, config, db_session):
        self.config = config
        self.db_session = db_session
        self.key_store_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 
                                           '../secure_storage/key_store.json')
        self.master_key_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 
                                           '../secure_storage/master.key')
        
        # Initialize key store if it doesn't exist
        self._initialize_key_store()
    
    def _initialize_key_store(self):
        """Initialize the key store and master key if they don't exist."""
        # Create secure storage directory if it doesn't exist
        os.makedirs(os.path.dirname(self.key_store_path), exist_ok=True)
        
        # Generate master key if it doesn't exist
        if not os.path.exists(self.master_key_path):
            master_key = Fernet.generate_key()
            with open(self.master_key_path, 'wb') as f:
                f.write(master_key)
            
            # Set secure permissions
            os.chmod(self.master_key_path, 0o600)
        
        # Initialize key store if it doesn't exist
        if not os.path.exists(self.key_store_path):
            empty_store = {
                'keys': {},
                'metadata': {
                    'created_at': datetime.utcnow().isoformat(),
                    'last_rotation': None
                }
            }
            
            # Encrypt and save
            self._save_key_store(empty_store)
            
            # Set secure permissions
            os.chmod(self.key_store_path, 0o600)
    
    def _load_master_key(self) -> bytes:
        """Load the master key used to encrypt the key store."""
        with open(self.master_key_path, 'rb') as f:
            return f.read()
    
    def _load_key_store(self) -> Dict:
        """Load and decrypt the key store."""
        # Load master key
        master_key = self._load_master_key()
        cipher = Fernet(master_key)
        
        # Load and decrypt key store
        with open(self.key_store_path, 'rb') as f:
            encrypted_data = f.read()
            
        decrypted_data = cipher.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode('utf-8'))
    
    def _save_key_store(self, key_store: Dict):
        """Encrypt and save the key store."""
        # Load master key
        master_key = self._load_master_key()
        cipher = Fernet(master_key)
        
        # Encrypt and save key store
        encrypted_data = cipher.encrypt(json.dumps(key_store).encode('utf-8'))
        with open(self.key_store_path, 'wb') as f:
            f.write(encrypted_data)
    
    def generate_data_key(self) -> Tuple[str, bytes]:
        """
        Generate a new data encryption key.
        
        Returns:
            Tuple containing:
                - key_id: Unique identifier for the key
                - key: The actual encryption key bytes
        """
        from services.encryption import EncryptionService
        
        # Create encryption service
        encryption_service = EncryptionService(self.config)
        
        # Generate key
        key = encryption_service.generate_data_key()
        key_id = str(uuid.uuid4())
        
        # Store key metadata
        key_store = self._load_key_store()
        key_store['keys'][key_id] = {
            'created_at': datetime.utcnow().isoformat(),
            'algorithm': 'AES-256-GCM',
            'status': 'ACTIVE',
            'key': b64encode(key).decode('utf-8')
        }
        self._save_key_store(key_store)
        
        return key_id, key
    
    def get_data_key(self, key_id: str) -> Optional[bytes]:
        """
        Retrieve a data encryption key by ID.
        
        Args:
            key_id: The unique identifier for the key
            
        Returns:
            The encryption key bytes or None if not found
        """
        key_store = self._load_key_store()
        
        if key_id in key_store['keys']:
            key_data = key_store['keys'][key_id]
            
            # Check if key is active
            if key_data['status'] == 'ACTIVE':
                return b64decode(key_data['key'])
            
        return None
    
    def rotate_key(self, key_id: str) -> Tuple[str, bytes]:
        """
        Rotate (replace) an existing encryption key.
        
        Args:
            key_id: The ID of the key to rotate
            
        Returns:
            Tuple containing:
                - new_key_id: Unique identifier for the new key
                - new_key: The new encryption key bytes
                
        Raises:
            ValueError: If the key doesn't exist
        """
        key_store = self._load_key_store()
        
        if key_id not in key_store['keys']:
            raise ValueError(f"Key with ID {key_id} not found")
        
        # Mark old key as deprecated
        key_store['keys'][key_id]['status'] = 'DEPRECATED'
        
        # Generate new key
        new_key_id, new_key = self.generate_data_key()
        
        # Update key store metadata
        key_store['metadata']['last_rotation'] = datetime.utcnow().isoformat()
        self._save_key_store(key_store)
        
        return new_key_id, new_key
    
    def revoke_key(self, key_id: str):
        """
        Revoke a key, making it unusable for future operations.
        
        Args:
            key_id: The ID of the key to revoke
            
        Raises:
            ValueError: If the key doesn't exist
        """
        key_store = self._load_key_store()
        
        if key_id not in key_store['keys']:
            raise ValueError(f"Key with ID {key_id} not found")
        
        # Mark key as revoked
        key_store['keys'][key_id]['status'] = 'REVOKED'
        key_store['keys'][key_id]['revoked_at'] = datetime.utcnow().isoformat()
        
        self._save_key_store(key_store)
    
    def list_keys(self, status: Optional[str] = None) -> List[Dict]:
        """
        List all keys or keys with a specific status.
        
        Args:
            status: Optional filter for key status
            
        Returns:
            List of key metadata (excluding the actual key material)
        """
        key_store = self._load_key_store()
        result = []
        
        for key_id, key_data in key_store['keys'].items():
            if status is None or key_data['status'] == status:
                # Create a copy without the actual key
                key_info = key_data.copy()
                key_info.pop('key')  # Remove actual key material
                key_info['key_id'] = key_id
                result.append(key_info)
        
        return result
    
    def backup_keys(self, backup_path: str, passphrase: str):
        """
        Create an encrypted backup of all keys.
        
        Args:
            backup_path: Path to save the backup
            passphrase: Password to encrypt the backup
        """
        key_store = self._load_key_store()
        
        # Create a hash of the passphrase for key derivation
        passphrase_hash = hashlib.sha256(passphrase.encode()).digest()
        backup_key = Fernet.generate_key()
        
        # Encrypt backup with passphrase-derived key
        cipher = Fernet(backup_key)
        encrypted_backup = cipher.encrypt(json.dumps(key_store).encode('utf-8'))
        
        # Create backup file with metadata
        backup_data = {
            'created_at': datetime.utcnow().isoformat(),
            'backup_key': b64encode(backup_key).decode('utf-8'),
            'data': b64encode(encrypted_backup).decode('utf-8')
        }
        
        with open(backup_path, 'w') as f:
            json.dump(backup_data, f)
    
    def restore_keys(self, backup_path: str, passphrase: str):
        """
        Restore keys from an encrypted backup.
        
        Args:
            backup_path: Path to the backup file
            passphrase: Password to decrypt the backup
            
        Raises:
            ValueError: If the backup is invalid or passphrase is incorrect
        """
        # Read backup file
        with open(backup_path, 'r') as f:
            backup_data = json.load(f)
        
        # Verify passphrase
        try:
            backup_key = b64decode(backup_data['backup_key'])
            encrypted_backup = b64decode(backup_data['data'])
            
            # Decrypt backup
            cipher = Fernet(backup_key)
            decrypted_data = cipher.decrypt(encrypted_backup)
            restored_key_store = json.loads(decrypted_data.decode('utf-8'))
            
            # Save restored keys
            self._save_key_store(restored_key_store)
            
        except Exception as e:
            raise ValueError(f"Failed to restore keys: {str(e)}")