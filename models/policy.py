from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, Table, JSON
from sqlalchemy.orm import relationship
from models import Base

class Policy(Base):
    __tablename__ = 'policies'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(128), unique=True, nullable=False)
    description = Column(String(256))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    creator_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    
    # The policy expression in attribute-based access control format
    # This is a JSON field that contains the access policy expression
    # Example: {"operation": "AND", "conditions": [{"attribute": "department", "value": "finance"}, 
    #                                             {"attribute": "clearance", "value": "secret"}]}
    policy_expression = Column(JSON, nullable=False)
    
    # Additional policy metadata
    is_active = Column(Boolean, default=True)
    priority = Column(Integer, default=1)  # Higher number means higher priority
    
    # Relationships
    creator = relationship("User")
    data = relationship("Data", secondary='data_policies', back_populates="policies")
    
    def __repr__(self):
        return f'<Policy {self.name}>'

class PolicyAudit(Base):
    __tablename__ = 'policy_audits'
    
    id = Column(Integer, primary_key=True)
    policy_id = Column(Integer, ForeignKey('policies.id'), nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    action = Column(String(32), nullable=False)  # 'create', 'update', 'delete', 'enforce'
    details = Column(Text, nullable=True)  # Additional details about the audit
    
    # Relationships
    policy = relationship("Policy")
    user = relationship("User")
    
    def __repr__(self):
        return f'<PolicyAudit {self.id} - {self.policy_id} - {self.action}>'