from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, LargeBinary, Table
from sqlalchemy.orm import relationship
from models import Base

# Association table for data and policies
data_policies = Table(
    'data_policies', 
    Base.metadata,
    Column('data_id', Integer, ForeignKey('data.id')),
    Column('policy_id', Integer, ForeignKey('policies.id'))
)

class Data(Base):
    __tablename__ = 'data'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(128), nullable=False)
    file_path = Column(String(256), nullable=False)
    file_type = Column(String(64), nullable=False)
    size = Column(Integer, nullable=False)  # Size in bytes
    description = Column(Text, nullable=True)  # Added description field
    encrypted = Column(Boolean, default=True)
    encrypted_key = Column(Text, nullable=True)  # Encrypted symmetric key
    iv = Column(String(32), nullable=True)  # Initialization vector
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    owner_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    content_hash = Column(String(64), nullable=True)  # For integrity verification
    
    # Relationships
    owner = relationship("User", back_populates="owned_data")
    policies = relationship("Policy", secondary=data_policies, back_populates="data")
    access_logs = relationship("AccessLog", back_populates="data")
    shares = relationship("FileShare", back_populates="file", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f'<Data {self.name}>'

class AccessLog(Base):
    __tablename__ = 'access_logs'
    
    id = Column(Integer, primary_key=True)
    data_id = Column(Integer, ForeignKey('data.id'), nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    action = Column(String(32), nullable=False)  # e.g., 'view', 'download', 'edit'
    success = Column(Boolean, default=True)
    ip_address = Column(String(45), nullable=True)  # IPv6 compatible
    user_agent = Column(String(256), nullable=True)
    
    # Relationships
    data = relationship("Data", back_populates="access_logs")
    user = relationship("User")
    
    def __repr__(self):
        return f'<AccessLog {self.id} - {self.data_id} - {self.action}>'

class FileShare(Base):
    """Model for tracking shared files between users."""
    __tablename__ = 'file_shares'
    
    id = Column(Integer, primary_key=True)
    file_id = Column(Integer, ForeignKey('data.id', ondelete='CASCADE'))
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'))
    permissions = Column(String(50), nullable=False, default='read')  # comma-separated list
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    policy_id = Column(Integer, ForeignKey('policies.id', ondelete='SET NULL'), nullable=True)
    
    # Relationships
    file = relationship("Data", back_populates="shares")
    user = relationship("User", backref="shared_files")
    policy = relationship("Policy", backref="file_shares")
    
    def __repr__(self):
        return f"<FileShare {self.file_id} shared with {self.user_id}>"