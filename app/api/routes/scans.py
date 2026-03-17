"""
Scan API Routes

Endpoints for managing and executing reconnaissance scans.

Routes:
- GET /api/scans - List all scans
- POST /api/scans - Start a new scan
- GET /api/scans/{id} - Get scan details
- POST /api/scans/{id}/stop - Stop a running scan
- GET /api/scans/{id}/logs - Get scan logs
- GET /api/scans/types - List available scan types
"""

import asyncio
from datetime import datetime
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field

from app.database import get_db, Scan, Project, ScanStatus, ScanType
from app.core.executor import executor


router = APIRouter(prefix="/api/scans", tags=["scans"])


# Store active scan tasks for cancellation
active_scans: Dict[int, asyncio.Task] = {}


# ===================
# Request/Response Models
# ===================

class ScanCreate(BaseModel):
    """Request model for creating a scan."""
    project_id: int = Field(..., description="Project to scan")
    scan_type: str = Field(..., description="Type of scan (subdomain, alive, urls, xss, sqli, etc.)")
    config: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Scan configuration options")


class ScanResponse(BaseModel):
    """Response model for a scan."""
    id: int
    project_id: int
    scan_type: str
    status: str
    started_at: Optional[str]
    completed_at: Optional[str]
    items_found: int
    error_message: Optional[str]
    tool_results: Dict[str, Any]
    config: Dict[str, Any]
    
    class Config:
        from_attributes = True


class ScanTypeInfo(BaseModel):
    """Information about a scan type."""
    name: str
    description: str
    tools: List[str]
    estimated_time: str
    requires_previous: Optional[str] = None


class LogsResponse(BaseModel):
    """Scan logs response."""
    scan_id: int
    logs: str


# ===================
# Scan Type Definitions
# ===================

SCAN_TYPES = {
    "subdomain": ScanTypeInfo(
        name="Subdomain Enumeration",
        description="Discover subdomains using multiple sources (subfinder, amass, crt.sh, etc.)",
        tools=["subfinder", "assetfinder", "amass", "crt.sh"],
        estimated_time="5-15 minutes",
    ),
    "alive": ScanTypeInfo(
        name="Alive Checking",
        description="Check which subdomains are responding and gather information",
        tools=["pdx", "naabu", "dnsx"],
        estimated_time="5-10 minutes",
        requires_previous="subdomain",
    ),
    "urls": ScanTypeInfo(
        name="URL Collection",
        description="Collect URLs from wayback machine, crawling, and other sources",
        tools=["waybackurls", "gau", "katana", "hakrawler", "gospider", "paramspider"],
        estimated_time="10-30 minutes",
        requires_previous="alive",
    ),
    "xss": ScanTypeInfo(
        name="XSS Scanning",
        description="Find Cross-Site Scripting vulnerabilities",
        tools=["dalfox", "kxss", "nuclei-xss"],
        estimated_time="30-60 minutes",
        requires_previous="urls",
    ),
    "sqli": ScanTypeInfo(
        name="SQL Injection",
        description="Detect SQL Injection vulnerabilities",
        tools=["sqlmap", "ghauri", "nuclei-sqli"],
        estimated_time="30-120 minutes",
        requires_previous="urls",
    ),
    "ssrf": ScanTypeInfo(
        name="SSRF Testing",
        description="Test for Server-Side Request Forgery",
        tools=["nuclei-ssrf"],
        estimated_time="15-30 minutes",
        requires_previous="urls",
    ),
    "lfi": ScanTypeInfo(
        name="LFI/Path Traversal",
        description="Test for Local File Inclusion vulnerabilities",
        tools=["ffuf-lfi", "nuclei-lfi"],
        estimated_time="15-30 minutes",
        requires_previous="urls",
    ),
    "fuzzing": ScanTypeInfo(
        name="Directory Fuzzing",
        description="Discover hidden directories and files",
        tools=["ffuf", "dirsearch"],
        estimated_time="30-60 minutes",
        requires_previous="alive",
    ),
    "nuclei": ScanTypeInfo(
        name="Nuclei Full Scan",
        description="Comprehensive vulnerability scan with all Nuclei templates",
        tools=["nuclei"],
        estimated_time="30-90 minutes",
        requires_previous="alive",
    ),
    "javascript": ScanTypeInfo(
        name="JavaScript Analysis",
        description="Analyze JavaScript files for secrets and endpoints",
        tools=["getjs", "linkfinder", "secretfinder"],
        estimated_time="15-30 minutes",
        requires_previous="urls",
    ),
    "api": ScanTypeInfo(
        name="API Testing",
        description="Discover and test API endpoints",
        tools=["arjun", "kiterunner", "ffuf"],
        estimated_time="20-45 minutes",
        requires_previous="urls",
    ),
    "cloud": ScanTypeInfo(
        name="Cloud Storage",
        description="Test for misconfigured cloud storage buckets",
        tools=["s3scanner", "cloud_enum"],
        estimated_time="10-20 minutes",
        requires_previous="subdomain",
    ),
    "full": ScanTypeInfo(
        name="Full Recon Pipeline",
        description="Run all scans in sequence: subdomain → alive → urls → all vulnerability scans",
        tools=["all"],
        estimated_time="2-4 hours",
    ),
}


# ===================
# Endpoints
# ===================

@router.get("/types", response_model=Dict[str, ScanTypeInfo])
async def list_scan_types():
    """Get all available scan types with their descriptions."""
    return SCAN_TYPES


@router.get("/tools")
async def check_tools():
    """Check which security tools are available on the system."""
    return await executor.check_all_tools()


@router.get("", response_model=List[ScanResponse])
async def list_scans(
    project_id: Optional[int] = None,
    status_filter: Optional[str] = None,
    scan_type: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db)
):
    """
    List all scans, optionally filtered by project, status, or type.
    """
    query = select(Scan).offset(skip).limit(limit).order_by(Scan.started_at.desc())
    
    if project_id:
        query = query.where(Scan.project_id == project_id)
    if status_filter:
        query = query.where(Scan.status == status_filter)
    if scan_type:
        query = query.where(Scan.scan_type == scan_type)
    
    result = await db.execute(query)
    scans = result.scalars().all()
    
    return [
        ScanResponse(
            id=scan.id,
            project_id=scan.project_id,
            scan_type=scan.scan_type,
            status=scan.status,
            started_at=scan.started_at.isoformat() if scan.started_at else None,
            completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
            items_found=scan.items_found,
            error_message=scan.error_message,
            tool_results=scan.tool_results or {},
            config=scan.config or {},
        )
        for scan in scans
    ]


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def start_scan(
    scan_request: ScanCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    """
    Start a new reconnaissance scan.
    
    The scan runs in the background. Use WebSocket or polling to monitor progress.
    """
    # Validate project exists
    project_result = await db.execute(
        select(Project).where(Project.id == scan_request.project_id)
    )
    project = project_result.scalar_one_or_none()
    
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )
    
    # Validate scan type
    if scan_request.scan_type not in SCAN_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid scan type. Valid types: {list(SCAN_TYPES.keys())}"
        )
    
    # Create scan record
    scan = Scan(
        project_id=scan_request.project_id,
        scan_type=scan_request.scan_type,
        status=ScanStatus.PENDING.value,
        config=scan_request.config or {},
    )
    
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    
    # Import here to avoid circular imports
    from app.core.pipeline import run_scan_pipeline
    
    # Start scan in background
    background_tasks.add_task(
        run_scan_pipeline,
        scan.id,
        project.target_domain,
        scan_request.scan_type,
        scan_request.config or {}
    )
    
    return ScanResponse(
        id=scan.id,
        project_id=scan.project_id,
        scan_type=scan.scan_type,
        status=scan.status,
        started_at=None,
        completed_at=None,
        items_found=0,
        error_message=None,
        tool_results={},
        config=scan.config or {},
    )


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Get details of a specific scan."""
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    return ScanResponse(
        id=scan.id,
        project_id=scan.project_id,
        scan_type=scan.scan_type,
        status=scan.status,
        started_at=scan.started_at.isoformat() if scan.started_at else None,
        completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
        items_found=scan.items_found,
        error_message=scan.error_message,
        tool_results=scan.tool_results or {},
        config=scan.config or {},
    )


@router.post("/{scan_id}/stop")
async def stop_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Stop a running scan."""
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    if scan.status != ScanStatus.RUNNING.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Scan is not running"
        )
    
    # Cancel the task if it's in our active scans
    if scan_id in active_scans:
        active_scans[scan_id].cancel()
        del active_scans[scan_id]
    
    # Update status
    scan.status = ScanStatus.CANCELLED.value
    scan.completed_at = datetime.now()
    scan.append_log("Scan cancelled by user")
    
    await db.commit()
    
    return {"message": "Scan stopped", "scan_id": scan_id}


@router.get("/{scan_id}/logs", response_model=LogsResponse)
async def get_scan_logs(
    scan_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Get the real-time logs for a scan."""
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    return LogsResponse(
        scan_id=scan_id,
        logs=scan.log_output or ""
    )
