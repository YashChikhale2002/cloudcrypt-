#!/usr/bin/env python
"""
Create an admin user for Crypt+ using direct SQL (avoiding ORM circular dependencies)
"""
import os
import sys
import sqlite3
import secrets
import string
import bcrypt
from datetime import datetime

# Add the current directory to the path so we can import our modules
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Import only what we need
from config import Config
from services.encryption import EncryptionService

def create_admin_user(username, email, password=None):
    """Create or update an admin user using direct SQL."""
    
    # Generate a random password if none provided
    if not password:
        password = ''.join(secrets.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(16))
        # Remove problematic characters for SQLite string handling
        password = password.replace("'", "").replace('"', "").replace('\\', "")
    
    # Hash the password using bcrypt (to match your User model)
    salt = bcrypt.gensalt()
    password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    # Generate key pair
    encryption_service = EncryptionService({'ENCRYPTION_KEY_SIZE': 256, 'RSA_KEY_SIZE': 2048})
    private_key, public_key = encryption_service.generate_key_pair()
    
    # Convert to strings
    private_key_str = private_key.decode('utf-8')
    public_key_str = public_key.decode('utf-8')
    
    # Extract database path from Config
    db_path = Config.SQLALCHEMY_DATABASE_URI.replace('sqlite:///', '')
    
    # Connect to the database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Check if users table has the required columns
    cursor.execute("PRAGMA table_info(users)")
    columns = [col[1] for col in cursor.fetchall()]
    
    # Add private_key and public_key columns if they don't exist
    if 'private_key' not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN private_key TEXT")
    
    if 'public_key' not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN public_key TEXT")
    
    # Check if user exists
    cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
    user = cursor.fetchone()
    
    # Format datetime in SQLite-compatible format (ISO 8601 without microseconds)
    current_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    
    if user:
        # Update existing user
        user_id = user[0]
        print(f"User {username} already exists with ID {user_id}. Updating to admin status.")
        
        cursor.execute("""
            UPDATE users 
            SET is_admin = 1, 
                is_active = 1, 
                password_hash = ?, 
                public_key = ?, 
                private_key = ?
            WHERE id = ?
        """, (password_hash, public_key_str, private_key_str, user_id))
    else:
        # Create new user
        print(f"Creating new admin user: {username}")
        
        cursor.execute("""
            INSERT INTO users (
                username, 
                email, 
                password_hash, 
                is_admin, 
                is_active, 
                public_key, 
                private_key, 
                created_at
            ) VALUES (?, ?, ?, 1, 1, ?, ?, ?)
        """, (
            username, 
            email, 
            password_hash, 
            public_key_str, 
            private_key_str, 
            current_time
        ))
    
    # Commit changes
    conn.commit()
    
    # Confirm the user was created/updated
    cursor.execute("SELECT id, is_admin FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    
    # Close connection
    conn.close()
    
    if result:
        user_id, is_admin = result
        admin_status = "is an admin" if is_admin else "is NOT an admin"
        print(f"User {username} (ID: {user_id}) {admin_status}")
        
        # Store private key in secure storage (optional)
        try:
            user_key_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), 
                f'secure_storage/user_keys/{username}.key'
            )
            os.makedirs(os.path.dirname(user_key_path), exist_ok=True)
            
            with open(user_key_path, 'wb') as f:
                f.write(private_key)
            
            # Set secure permissions
            os.chmod(user_key_path, 0o600)
            print(f"Private key stored at: {user_key_path}")
        except Exception as e:
            print(f"Warning: Could not store private key file: {str(e)}")
        
        print(f"\nAdmin user '{username}' has been created/updated successfully.")
        print(f"Email: {email}")
        print(f"Password: {password}")
        print(f"Login URL: http://127.0.0.1:5000/auth/login")
    else:
        print("Error: Failed to create/update user.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python create_admin_direct.py <username> <email> [password]")
        sys.exit(1)
    
    username = sys.argv[1]
    email = sys.argv[2]
    
    # Check if password is provided
    password = None
    if len(sys.argv) > 3:
        password = sys.argv[3]
    
    create_admin_user(username, email, password)