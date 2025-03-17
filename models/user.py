from datetime import datetime
from flask_login import UserMixin
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, Table
from sqlalchemy.orm import relationship
import bcrypt
from models import Base

# Association table for user attributes
user_attributes = Table(
    'user_attributes', 
    Base.metadata,
    Column('user_id', Integer, ForeignKey('users.id')),
    Column('attribute_id', Integer, ForeignKey('attributes.id'))
)

class User(Base, UserMixin):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(128), nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    public_key = Column(Text, nullable=True)  # For storing user's public key
    
    # Relationships
    attributes = relationship("Attribute", secondary=user_attributes, back_populates="users")
    owned_data = relationship("Data", back_populates="owner")
    
    def set_password(self, password):
        """Hash the password and store it in the database."""
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
        self.password_hash = password_hash.decode('utf-8')
    
    def check_password(self, password):
        """Verify the password against its hash."""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
    
    def has_attribute(self, attribute_name):
        """Check if user has a specific attribute."""
        return any(attr.name == attribute_name for attr in self.attributes)
    
    def __repr__(self):
        return f'<User {self.username}>'


class Attribute(Base):
    __tablename__ = 'attributes'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False)
    description = Column(String(256))
    
    # Relationships
    users = relationship("User", secondary=user_attributes, back_populates="attributes")
    
    def __repr__(self):
        return f'<Attribute {self.name}>'