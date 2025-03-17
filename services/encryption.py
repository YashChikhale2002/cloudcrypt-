import os
import hashlib
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from typing import Tuple, Dict, Any

class EncryptionService:
    """Service for encrypting and decrypting data using attribute-based encryption."""
    
    def __init__(self, config):
        """
        Initialize the encryption service.
        
        Args:
            config: Either a Config object or a dictionary with configuration values
        """
        # Handle both dictionary and object configurations
        if isinstance(config, dict):
            self.key_size = config.get('ENCRYPTION_KEY_SIZE', 256) // 8  # Convert bits to bytes
            self.rsa_key_size = config.get('RSA_KEY_SIZE', 2048)
        else:
            # Try to get attributes, with defaults if they don't exist
            self.key_size = getattr(config, 'ENCRYPTION_KEY_SIZE', 256) // 8
            self.rsa_key_size = getattr(config, 'RSA_KEY_SIZE', 2048)
    
    def generate_data_key(self) -> bytes:
        """Generate a random symmetric key for data encryption."""
        return get_random_bytes(self.key_size)
    
    def generate_key_pair(self) -> Tuple[bytes, bytes]:
        """Generate RSA key pair for asymmetric encryption."""
        key = RSA.generate(self.rsa_key_size)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key
    
    def encrypt_file(self, file_path: str, key: bytes) -> Dict[str, Any]:
        """
        Encrypt a file using AES-GCM.
        
        Args:
            file_path: Path to the file to encrypt
            key: Symmetric key for encryption
            
        Returns:
            Dictionary containing:
                - encrypted_file_path: Path to the encrypted file
                - iv: Initialization vector
                - tag: Authentication tag
                - content_hash: Hash of original content for integrity verification
        """
        # Generate IV (Initialization Vector)
        iv = get_random_bytes(16)
        
        # Create cipher
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        
        # Read file
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Calculate hash of original content
        content_hash = hashlib.sha256(data).hexdigest()
        
        # Encrypt file
        ciphertext, tag = cipher.encrypt_and_digest(data)
        
        # Save encrypted file
        encrypted_file_path = f"{file_path}.encrypted"
        with open(encrypted_file_path, 'wb') as f:
            f.write(ciphertext)
        
        return {
            'encrypted_file_path': encrypted_file_path,
            'iv': b64encode(iv).decode('utf-8'),
            'tag': b64encode(tag).decode('utf-8'),
            'content_hash': content_hash
        }
    
    def decrypt_file(self, encrypted_file_path: str, key: bytes, iv: str, tag: str) -> str:
        """
        Decrypt a file using AES-GCM.
        
        Args:
            encrypted_file_path: Path to the encrypted file
            key: Symmetric key for decryption
            iv: Base64-encoded initialization vector
            tag: Base64-encoded authentication tag
            
        Returns:
            Path to the decrypted file
        """
        # Decode IV and tag
        iv_bytes = b64decode(iv)
        tag_bytes = b64decode(tag)
        
        # Create cipher
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv_bytes)
        
        # Read encrypted file
        with open(encrypted_file_path, 'rb') as f:
            ciphertext = f.read()
        
        # Decrypt file
        plaintext = cipher.decrypt_and_verify(ciphertext, tag_bytes)
        
        # Save decrypted file
        decrypted_file_path = encrypted_file_path.replace('.encrypted', '.decrypted')
        with open(decrypted_file_path, 'wb') as f:
            f.write(plaintext)
        
        return decrypted_file_path
    
    def encrypt_key(self, data_key: bytes, public_key: bytes) -> str:
        """
        Encrypt the data key with a user's public key.
        
        Args:
            data_key: Symmetric key used for data encryption
            public_key: User's public key
            
        Returns:
            Base64-encoded encrypted key
        """
        # Import public key
        recipient_key = RSA.import_key(public_key)
        
        # Create cipher
        cipher = PKCS1_OAEP.new(recipient_key)
        
        # Encrypt data key
        encrypted_key = cipher.encrypt(data_key)
        
        # Encode encrypted key
        return b64encode(encrypted_key).decode('utf-8')
    
    def decrypt_key(self, encrypted_key: str, private_key: bytes) -> bytes:
        """
        Decrypt the data key with a user's private key.
        
        Args:
            encrypted_key: Base64-encoded encrypted data key
            private_key: User's private key
            
        Returns:
            Decrypted data key
        """
        # Decode encrypted key
        encrypted_key_bytes = b64decode(encrypted_key)
        
        # Import private key
        user_key = RSA.import_key(private_key)
        
        # Create cipher
        cipher = PKCS1_OAEP.new(user_key)
        
        # Decrypt data key
        return cipher.decrypt(encrypted_key_bytes)
    
    def verify_file_integrity(self, file_path: str, content_hash: str) -> bool:
        """
        Verify the integrity of a file using its hash.
        
        Args:
            file_path: Path to the file
            content_hash: Expected hash value
            
        Returns:
            True if integrity check passes, False otherwise
        """
        with open(file_path, 'rb') as f:
            data = f.read()
        
        calculated_hash = hashlib.sha256(data).hexdigest()
        return calculated_hash == content_hash