"""
Database Models and Connection Management

This module defines:
- SQLAlchemy ORM models for all database tables
- Async database engine and session management
- Database initialization and migration helpers

Database Schema:
- Project: Top-level container for a target domain
- Scan: Individual scan execution within a project
- Subdomain: Discovered subdomains
- URL: Collected URLs from various sources
- Vulnerability: Found security issues
"""

import json
from datetime import datetime
from typing import Optional, List, Any
from enum import Enum

from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Boolean, 
    ForeignKey, Enum as SQLEnum, JSON, Index, create_engine
)
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker

from app.config import settings


# ===================
# Enums
# ===================

class ScanStatus(str, Enum):
    """Status of a scan execution."""
    PENDING = "pending"       # Queued but not started
    RUNNING = "running"       # Currently executing
    COMPLETED = "completed"   # Finished successfully
    FAILED = "failed"         # Finished with errors
    CANCELLED = "cancelled"   # Manually stopped


class ScanType(str, Enum):
    """Types of scans available."""
    SUBDOMAIN = "subdomain"           # Subdomain enumeration
    ALIVE = "alive"                   # Alive checking
    URLS = "urls"                     # URL collection
    XSS = "xss"                       # XSS scanning
    SQLI = "sqli"                     # SQL injection
    SSRF = "ssrf"                     # SSRF testing
    LFI = "lfi"                       # LFI/Path traversal
    SSTI = "ssti"                     # Template injection
    CMDI = "cmdi"                     # Command injection
    REDIRECT = "redirect"             # Open redirect
    FUZZING = "fuzzing"               # Directory/param fuzzing
    NUCLEI = "nuclei"                 # Nuclei scanning
    JAVASCRIPT = "javascript"         # JS analysis
    API = "api"                       # API testing
    CLOUD = "cloud"                   # Cloud storage testing
    FULL = "full"                     # Full pipeline


class Severity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ===================
# Base Model
# ===================

Base = declarative_base()


# ===================
# Models
# ===================

class Project(Base):
    """
    Project Model - Top-level container for reconnaissance.
    
    A project represents a single target domain and contains
    all related scans, subdomains, URLs, and vulnerabilities.
    
    Attributes:
        id: Unique identifier
        name: Human-readable project name
        target_domain: The main domain to scan (e.g., example.com)
        description: Optional notes about the project
        created_at: When the project was created
        updated_at: Last modification time
        status: Current project status
    """
    __tablename__ = "projects"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    target_domain = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    status = Column(String(50), default="active")
    
    # Relationships
    scans = relationship("Scan", back_populates="project", cascade="all, delete-orphan")
    subdomains = relationship("Subdomain", back_populates="project", cascade="all, delete-orphan")
    urls = relationship("URL", back_populates="project", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="project", cascade="all, delete-orphan")
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "name": self.name,
            "target_domain": self.target_domain,
            "description": self.description,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "status": self.status,
            "scan_count": len(self.scans) if self.scans else 0,
            "subdomain_count": len(self.subdomains) if self.subdomains else 0,
            "url_count": len(self.urls) if self.urls else 0,
            "vulnerability_count": len(self.vulnerabilities) if self.vulnerabilities else 0,
        }


class Scan(Base):
    """
    Scan Model - Individual scan execution.
    
    Represents a single scan run (e.g., subdomain enumeration,
    nuclei scan, etc.) with its status, logs, and results.
    
    Attributes:
        id: Unique identifier
        project_id: Parent project reference
        scan_type: Type of scan (subdomain, nuclei, etc.)
        status: Current execution status
        started_at: When the scan started
        completed_at: When the scan finished
        log_output: Real-time log output
        tool_results: JSON object with per-tool results
        error_message: Error details if failed
    """
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False, index=True)
    scan_type = Column(String(50), nullable=False, index=True)
    status = Column(String(50), default=ScanStatus.PENDING.value, index=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    log_output = Column(Text, default="")
    tool_results = Column(JSON, default=dict)  # {tool_name: {status, output, count}}
    error_message = Column(Text, nullable=True)
    
    # Configuration used for this scan
    config = Column(JSON, default=dict)
    
    # Statistics
    items_found = Column(Integer, default=0)
    
    # Relationships
    project = relationship("Project", back_populates="scans")
    
    # Indexes for common queries
    __table_args__ = (
        Index("ix_scans_project_status", "project_id", "status"),
    )
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "project_id": self.project_id,
            "scan_type": self.scan_type,
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "tool_results": self.tool_results,
            "error_message": self.error_message,
            "items_found": self.items_found,
            "config": self.config,
        }
    
    def append_log(self, message: str):
        """Append a message to the log output."""
        timestamp = datetime.utcnow().strftime("%H:%M:%S")
        self.log_output = (self.log_output or "") + f"[{timestamp}] {message}\n"


class Subdomain(Base):
    """
    Subdomain Model - Discovered subdomains.
    
    Stores all discovered subdomains with their properties
    like IP address, HTTP status, technology stack, etc.
    
    Attributes:
        id: Unique identifier
        project_id: Parent project reference
        subdomain: The subdomain (e.g., api.example.com)
        source: Which tool discovered it
        is_alive: Whether it responds to HTTP
        ip_address: Resolved IP address
        status_code: HTTP status code
        title: Page title
        tech_stack: Detected technologies (JSON array)
        content_length: Response size
        cdn: Whether behind CDN
    """
    __tablename__ = "subdomains"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False, index=True)
    subdomain = Column(String(500), nullable=False, index=True)
    source = Column(String(100), nullable=True)  # Tool that found it
    
    # Alive check results
    is_alive = Column(Boolean, default=False)
    ip_address = Column(String(50), nullable=True)
    status_code = Column(Integer, nullable=True)
    title = Column(String(500), nullable=True)
    tech_stack = Column(JSON, default=list)  # ["nginx", "PHP", "WordPress"]
    content_length = Column(Integer, nullable=True)
    cdn = Column(String(100), nullable=True)  # Cloudflare, Akamai, etc.
    
    # Additional info
    cname = Column(String(500), nullable=True)
    takeover_vulnerable = Column(Boolean, default=False)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    project = relationship("Project", back_populates="subdomains")
    
    # Unique constraint on project + subdomain
    __table_args__ = (
        Index("ix_subdomains_unique", "project_id", "subdomain", unique=True),
    )
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "project_id": self.project_id,
            "subdomain": self.subdomain,
            "source": self.source,
            "is_alive": self.is_alive,
            "ip_address": self.ip_address,
            "status_code": self.status_code,
            "title": self.title,
            "tech_stack": self.tech_stack,
            "content_length": self.content_length,
            "cdn": self.cdn,
            "takeover_vulnerable": self.takeover_vulnerable,
        }


class URL(Base):
    """
    URL Model - Collected URLs.
    
    Stores URLs discovered from various sources like
    Wayback Machine, crawlers, and JS analysis.
    
    Attributes:
        id: Unique identifier
        project_id: Parent project reference
        url: The full URL
        source: Which tool/source found it
        status_code: HTTP status (if checked)
        content_type: Response content type
        has_params: Whether URL has query parameters
        param_names: List of parameter names
    """
    __tablename__ = "urls"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False, index=True)
    url = Column(Text, nullable=False)
    source = Column(String(100), nullable=True)
    
    # URL classification
    status_code = Column(Integer, nullable=True)
    content_type = Column(String(200), nullable=True)
    has_params = Column(Boolean, default=False)
    param_names = Column(JSON, default=list)  # ["id", "page", "q"]
    
    # File type detection
    file_type = Column(String(50), nullable=True)  # js, json, xml, etc.
    is_api = Column(Boolean, default=False)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    project = relationship("Project", back_populates="urls")
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "project_id": self.project_id,
            "url": self.url,
            "source": self.source,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "has_params": self.has_params,
            "param_names": self.param_names,
            "file_type": self.file_type,
            "is_api": self.is_api,
        }


class Vulnerability(Base):
    """
    Vulnerability Model - Found security issues.
    
    Stores all discovered vulnerabilities with details
    for reporting and verification.
    
    Attributes:
        id: Unique identifier
        project_id: Parent project reference
        scan_id: Which scan found it
        vuln_type: Type of vulnerability (XSS, SQLi, etc.)
        severity: Severity level (critical, high, medium, low, info)
        url: Affected URL
        parameter: Vulnerable parameter name
        payload: Proof of concept payload
        evidence: Response evidence
        tool: Tool that found it
        template_id: Nuclei template ID (if applicable)
        verified: Manual verification status
        notes: Additional notes
    """
    __tablename__ = "vulnerabilities"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True, index=True)
    
    vuln_type = Column(String(100), nullable=False, index=True)
    severity = Column(String(20), default=Severity.INFO.value, index=True)
    
    # Vulnerability details
    url = Column(Text, nullable=False)
    parameter = Column(String(200), nullable=True)
    payload = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    
    # Discovery info
    tool = Column(String(100), nullable=True)
    template_id = Column(String(200), nullable=True)  # nuclei template
    
    # Verification
    verified = Column(Boolean, default=False)
    false_positive = Column(Boolean, default=False)
    notes = Column(Text, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    project = relationship("Project", back_populates="vulnerabilities")
    
    # Indexes
    __table_args__ = (
        Index("ix_vulns_severity", "project_id", "severity"),
    )
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "project_id": self.project_id,
            "scan_id": self.scan_id,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence,
            "tool": self.tool,
            "template_id": self.template_id,
            "verified": self.verified,
            "false_positive": self.false_positive,
            "notes": self.notes,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


# ===================
# Database Engine
# ===================

# Async engine for FastAPI
async_engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    future=True
)

# Async session factory
AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False
)


async def init_db():
    """
    Initialize the database.
    
    Creates all tables if they don't exist.
    Should be called on application startup.
    """
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db() -> AsyncSession:
    """
    Dependency for getting database sessions.
    
    Usage in FastAPI:
        @app.get("/items")
        async def get_items(db: AsyncSession = Depends(get_db)):
            ...
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
