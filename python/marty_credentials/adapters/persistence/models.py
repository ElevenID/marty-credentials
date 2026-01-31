"""SQLAlchemy models for credential persistence"""
from datetime import datetime
from enum import Enum as PyEnum
from typing import Dict, Any, Optional

from sqlalchemy import (
    Column, Integer, String, DateTime, Text, ForeignKey, Enum, JSON, Boolean
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class CredentialType(PyEnum):
    """Supported credential types"""
    W3C_VC = "w3c_vc"
    SD_JWT = "sd_jwt"
    MDOC = "mdoc"
    OPENID4VP = "openid4vp"
    JWT = "jwt"
    OPEN_BADGE_V2 = "open_badge_v2"
    OPEN_BADGE_V3 = "open_badge_v3"
    LONGFELLOW_ZK = "longfellow_zk"


class CredentialStatus(PyEnum):
    """Credential status values"""
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"
    SUSPENDED = "suspended"


class VerificationResult(PyEnum):
    """Verification outcome"""
    SUCCESS = "success"
    FAILED = "failed"
    ERROR = "error"
    ZK_PROOF_VALID = "zk_proof_valid"


class Holder(Base):
    """Credential holder entity"""
    __tablename__ = "holders"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    did = Column(String(255), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    credentials = relationship("Credential", back_populates="holder", cascade="all, delete-orphan")


class Credential(Base):
    """Credential entity"""
    __tablename__ = "credentials"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    type = Column(Enum(CredentialType), nullable=False, index=True)
    issuer_did = Column(String(255), nullable=False, index=True)
    holder_id = Column(Integer, ForeignKey("holders.id"), nullable=False)
    
    # Credential content
    claims = Column(JSON, nullable=False)
    raw_credential = Column(Text, nullable=False)  # JWT, CBOR, or JSON-LD
    
    # Status
    status = Column(Enum(CredentialStatus), default=CredentialStatus.ACTIVE, nullable=False, index=True)
    
    # Timestamps
    issued_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=True)
    revoked_at = Column(DateTime, nullable=True)
    
    # Selective disclosure info (for SD-JWT)
    selective_disclosure_keys = Column(JSON, nullable=True)
    
    # Relationships
    holder = relationship("Holder", back_populates="credentials")
    verification_logs = relationship("VerificationLog", back_populates="credential", cascade="all, delete-orphan")


class VerificationLog(Base):
    """Log of verification attempts"""
    __tablename__ = "verification_logs"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    credential_id = Column(Integer, ForeignKey("credentials.id"), nullable=True)
    verifier = Column(String(255), nullable=False, index=True)
    result = Column(Enum(VerificationResult), nullable=False, index=True)
    details = Column(JSON, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # Relationships
    credential = relationship("Credential", back_populates="verification_logs")


class TrustRegistry(Base):
    """Trust registry for issuer/verifier trust relationships"""
    __tablename__ = "trust_registry"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    entity_did = Column(String(255), nullable=False, index=True)
    entity_type = Column(String(50), nullable=False)  # 'issuer' or 'verifier'
    trusted_by = Column(String(255), nullable=False)  # DID of trusting party
    credential_types = Column(JSON, nullable=True)  # List of credential types this entity is trusted for
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)


class ZkChallenge(Base):
    """ZK proof challenge session for interactive verification"""
    __tablename__ = "zk_challenges"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(255), unique=True, nullable=False, index=True)
    nonce = Column(Text, nullable=False)  # Base64 encoded nonce
    doctype = Column(String(255), nullable=False)
    verifier_id = Column(String(255), nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False, index=True)
    used = Column(Boolean, default=False, nullable=False)
