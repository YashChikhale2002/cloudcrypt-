#!/usr/bin/env python3
import argparse
import sys
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text, ForeignKey, Table
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import bcrypt
import os

# Create a standalone Base
Base = declarative_base()

# Create minimal models needed for admin user creation
# This avoids circular import issues
class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(128), nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    public_key = Column(Text, nullable=True)
    
    def set_password(self, password):
        """Hash the password and store it in the database."""
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
        self.password_hash = password_hash.decode('utf-8')

# Attribute model
class Attribute(Base):
    __tablename__ = 'attributes'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False)
    description = Column(String(256))
    
# Association table for user attributes
user_attributes = Table(
    'user_attributes', 
    Base.metadata,
    Column('user_id', Integer, ForeignKey('users.id')),
    Column('attribute_id', Integer, ForeignKey('attributes.id'))
)

# Add relationships after both classes are defined
User.attributes = relationship("Attribute", secondary=user_attributes)

def create_admin_user(db_uri, username, email, password, attributes=None):
    """
    Create an admin user in the database.
    
    Args:
        db_uri (str): Database URI
        username (str): Admin username
        email (str): Admin email
        password (str): Admin password
        attributes (list): List of attribute names to assign to the admin
    """
    # Create database connection
    engine = create_engine(db_uri)
    Session = sessionmaker(bind=engine)
    session = Session()
    
    try:
        # Check if user already exists
        existing_user = session.query(User).filter(
            (User.username == username) | (User.email == email)
        ).first()
        
        if existing_user:
            print(f"Error: User with username '{username}' or email '{email}' already exists.")
            return False
        
        # Create new admin user
        admin_user = User(
            username=username,
            email=email,
            is_active=True,
            is_admin=True,
            created_at=datetime.utcnow()
        )
        
        # Set password
        admin_user.set_password(password)
        
        # Add user to session
        session.add(admin_user)
        
        # Add attributes if provided
        if attributes:
            for attr_name in attributes:
                # Check if attribute exists, create it if not
                attr = session.query(Attribute).filter_by(name=attr_name).first()
                if not attr:
                    attr = Attribute(name=attr_name, description=f"{attr_name} attribute")
                    session.add(attr)
                    session.flush()  # Flush to get the ID
                
                # Add attribute to user
                admin_user.attributes.append(attr)
        
        # Commit changes
        session.commit()
        print(f"Admin user '{username}' successfully created!")
        return True
        
    except Exception as e:
        session.rollback()
        print(f"Error creating admin user: {str(e)}")
        return False
        
    finally:
        session.close()

def main():
    """Main function to handle command line arguments and create admin user."""
    parser = argparse.ArgumentParser(description='Create an admin user for Crypt+')
    parser.add_argument('--db-uri', required=True, help='Database URI (e.g., sqlite:///crypt_plus.db)')
    parser.add_argument('--username', required=True, help='Admin username')
    parser.add_argument('--email', required=True, help='Admin email')
    parser.add_argument('--password', required=True, help='Admin password')
    parser.add_argument('--attributes', nargs='*', help='List of attributes to assign to the admin')
    
    args = parser.parse_args()
    
    success = create_admin_user(
        args.db_uri,
        args.username,
        args.email,
        args.password,
        args.attributes
    )
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()