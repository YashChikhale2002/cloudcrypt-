# fix_encrypted_files.py
import os
import sys
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from config import Config

# Set up path to make sure modules can be imported
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Import your models
from models.data import Data
from models.user import User
from services.encryption import EncryptionService
from services.key_management import KeyManagementService

print("Starting file re-encryption script...")

# Create database connection
engine = create_engine(Config.SQLALCHEMY_DATABASE_URI)
Session = sessionmaker(bind=engine)
session = Session()

# Initialize services
encryption_service = EncryptionService({'ENCRYPTION_KEY_SIZE': 256, 'RSA_KEY_SIZE': 2048})
key_management_service = KeyManagementService(Config, session)

# Get all encrypted files
encrypted_files = session.query(Data).filter_by(encrypted=True).all()
print(f"Found {len(encrypted_files)} encrypted files")

for data in encrypted_files:
    print(f"\nProcessing file: {data.name} (ID: {data.id})")
    
    # Get the owner
    owner = session.query(User).get(data.owner_id)
    if not owner:
        print(f"  Owner not found for file {data.id}, skipping")
        continue
    
    print(f"  Owner: {owner.username} (ID: {owner.id})")
    
    # Check if owner has keys
    if not hasattr(owner, 'public_key') or not owner.public_key:
        print(f"  Owner has no public key, skipping")
        continue
    
    try:
        # Generate new data key
        key_id, data_key = key_management_service.generate_data_key()
        
        # Encrypt the data key with the owner's public key
        user_public_key = owner.public_key.encode('utf-8')
        encrypted_key = encryption_service.encrypt_key(data_key, user_public_key)
        
        # Update the file's encrypted key
        data.encrypted_key = encrypted_key
        
        # Note: We're not re-encrypting the file content itself, just updating the key
        print(f"  Updated encryption key for file {data.id}")
    
    except Exception as e:
        print(f"  Error updating file {data.id}: {str(e)}")
        continue

# Commit changes
session.commit()
print("\nFile re-encryption completed!")