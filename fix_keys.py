# fix_keys.py - Modified version
import os
import sys
from sqlalchemy import create_engine, Column, Text, Table, MetaData, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Set up path to make sure modules can be imported
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Import the Config
from config import Config

print("Starting key fix script...")

# Create database connection
engine = create_engine(Config.SQLALCHEMY_DATABASE_URI)
Session = sessionmaker(bind=engine)
session = Session()

# Step 1: Add columns to the User model if they don't exist
try:
    # Check if columns exist (for SQLite)
    result = engine.execute(text("PRAGMA table_info(users)")).fetchall()
    columns = [r[1] for r in result]
    
    if 'private_key' not in columns:
        print("Adding private_key column to users table")
        engine.execute(text("ALTER TABLE users ADD COLUMN private_key TEXT"))
    else:
        print("private_key column already exists")
    
    if 'public_key' not in columns:
        print("Adding public_key column to users table")
        engine.execute(text("ALTER TABLE users ADD COLUMN public_key TEXT"))
    else:
        print("public_key column already exists")
except Exception as e:
    print(f"Error checking or adding columns: {str(e)}")
    sys.exit(1)

# Step 2: Generate keys for all users using direct SQL to avoid ORM issues
print("\nGenerating keys for users...")

try:
    # Import here to avoid circular imports
    from services.encryption import EncryptionService
    
    # Create encryption service
    encryption_service = EncryptionService({'ENCRYPTION_KEY_SIZE': 256, 'RSA_KEY_SIZE': 2048})
    
    # Get all users directly with SQL
    users_result = engine.execute(text("SELECT id, username FROM users")).fetchall()
    print(f"Found {len(users_result)} users")
    
    updated_count = 0
    for user in users_result:
        user_id = user[0]
        username = user[1]
        print(f"Processing user: {username} (ID: {user_id})")
        
        # Check if user already has keys
        key_check = engine.execute(
            text("SELECT private_key, public_key FROM users WHERE id = :user_id"),
            {"user_id": user_id}
        ).fetchone()
        
        has_private_key = key_check[0] is not None and key_check[0] != ""
        has_public_key = key_check[1] is not None and key_check[1] != ""
        
        if not has_private_key or not has_public_key:
            print(f"  Generating new keys for user: {username}")
            private_key, public_key = encryption_service.generate_key_pair()
            
            # Convert bytes to string for storage
            private_key_str = private_key.decode('utf-8')
            public_key_str = public_key.decode('utf-8')
            
            # Update user with new keys
            engine.execute(
                text("UPDATE users SET private_key = :private_key, public_key = :public_key WHERE id = :user_id"),
                {"private_key": private_key_str, "public_key": public_key_str, "user_id": user_id}
            )
            updated_count += 1
    
    print(f"\nUpdated keys for {updated_count} users")
    
    # Verify changes
    print("\nVerifying user keys:")
    verified_users = engine.execute(text("SELECT id, username, private_key, public_key FROM users")).fetchall()
    for user in verified_users:
        user_id = user[0]
        username = user[1]
        private_key = user[2]
        public_key = user[3]
        
        print(f"User {username} (ID: {user_id})")
        print(f"  Private key: {'Set' if private_key else 'Not set'}")
        print(f"  Public key: {'Set' if public_key else 'Not set'}")
    
except Exception as e:
    print(f"Error generating keys: {str(e)}")
    sys.exit(1)

print("\nKey fix completed successfully!")