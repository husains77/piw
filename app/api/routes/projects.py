"""
Project API Routes

Endpoints for managing reconnaissance projects.

Routes:
- GET /api/projects - List all projects
- POST /api/projects - Create new project
- GET /api/projects/{id} - Get project details
- PUT /api/projects/{id} - Update project
- DELETE /api/projects/{id} - Delete project
- GET /api/projects/{id}/stats - Get project statistics
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from pydantic import BaseModel, Field

from app.database import get_db, Project, Scan, Subdomain, URL, Vulnerability


router = APIRouter(prefix="/api/projects", tags=["projects"])


# ===================
# Request/Response Models
# ===================

class ProjectCreate(BaseModel):
    """Request model for creating a project."""
    name: str = Field(..., min_length=1, max_length=255, description="Project name")
    target_domain: str = Field(..., min_length=1, max_length=255, description="Target domain (e.g., example.com)")
    description: Optional[str] = Field(None, max_length=2000, description="Project description")


class ProjectUpdate(BaseModel):
    """Request model for updating a project."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    target_domain: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=2000)
    status: Optional[str] = Field(None, max_length=50)


class ProjectResponse(BaseModel):
    """Response model for a project."""
    id: int
    name: str
    target_domain: str
    description: Optional[str]
    created_at: Optional[str]
    updated_at: Optional[str]
    status: str
    scan_count: int = 0
    subdomain_count: int = 0
    url_count: int = 0
    vulnerability_count: int = 0
    
    class Config:
        from_attributes = True


class ProjectStats(BaseModel):
    """Statistics for a project."""
    total_scans: int
    completed_scans: int
    failed_scans: int
    running_scans: int
    total_subdomains: int
    alive_subdomains: int
    total_urls: int
    urls_with_params: int
    total_vulnerabilities: int
    critical_vulns: int
    high_vulns: int
    medium_vulns: int
    low_vulns: int


# ===================
# Endpoints
# ===================

@router.get("", response_model=List[ProjectResponse])
async def list_projects(
    skip: int = 0,
    limit: int = 100,
    status_filter: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    List all projects.
    
    - **skip**: Number of projects to skip (pagination)
    - **limit**: Maximum number of projects to return
    - **status_filter**: Filter by project status (active, archived)
    """
    query = select(Project).offset(skip).limit(limit).order_by(Project.created_at.desc())
    
    if status_filter:
        query = query.where(Project.status == status_filter)
    
    result = await db.execute(query)
    projects = result.scalars().all()
    
    # Get counts for each project
    response = []
    for project in projects:
        # Count related items
        scan_count = await db.scalar(
            select(func.count(Scan.id)).where(Scan.project_id == project.id)
        )
        subdomain_count = await db.scalar(
            select(func.count(Subdomain.id)).where(Subdomain.project_id == project.id)
        )
        url_count = await db.scalar(
            select(func.count(URL.id)).where(URL.project_id == project.id)
        )
        vuln_count = await db.scalar(
            select(func.count(Vulnerability.id)).where(Vulnerability.project_id == project.id)
        )
        
        response.append(ProjectResponse(
            id=project.id,
            name=project.name,
            target_domain=project.target_domain,
            description=project.description,
            created_at=project.created_at.isoformat() if project.created_at else None,
            updated_at=project.updated_at.isoformat() if project.updated_at else None,
            status=project.status,
            scan_count=scan_count or 0,
            subdomain_count=subdomain_count or 0,
            url_count=url_count or 0,
            vulnerability_count=vuln_count or 0,
        ))
    
    return response


@router.post("", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def create_project(
    project: ProjectCreate,
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new reconnaissance project.
    
    - **name**: Human-readable project name
    - **target_domain**: The main domain to scan (e.g., example.com)
    - **description**: Optional notes about the project
    """
    # Validate domain format
    import re
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    if not domain_pattern.match(project.target_domain):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid domain format"
        )
    
    # Create project
    db_project = Project(
        name=project.name,
        target_domain=project.target_domain,
        description=project.description,
    )
    
    db.add(db_project)
    await db.commit()
    await db.refresh(db_project)
    
    return ProjectResponse(
        id=db_project.id,
        name=db_project.name,
        target_domain=db_project.target_domain,
        description=db_project.description,
        created_at=db_project.created_at.isoformat() if db_project.created_at else None,
        updated_at=db_project.updated_at.isoformat() if db_project.updated_at else None,
        status=db_project.status,
        scan_count=0,
        subdomain_count=0,
        url_count=0,
        vulnerability_count=0,
    )


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(
    project_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Get a specific project by ID."""
    result = await db.execute(
        select(Project).where(Project.id == project_id)
    )
    project = result.scalar_one_or_none()
    
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )
    
    # Get counts
    scan_count = await db.scalar(
        select(func.count(Scan.id)).where(Scan.project_id == project.id)
    )
    subdomain_count = await db.scalar(
        select(func.count(Subdomain.id)).where(Subdomain.project_id == project.id)
    )
    url_count = await db.scalar(
        select(func.count(URL.id)).where(URL.project_id == project.id)
    )
    vuln_count = await db.scalar(
        select(func.count(Vulnerability.id)).where(Vulnerability.project_id == project.id)
    )
    
    return ProjectResponse(
        id=project.id,
        name=project.name,
        target_domain=project.target_domain,
        description=project.description,
        created_at=project.created_at.isoformat() if project.created_at else None,
        updated_at=project.updated_at.isoformat() if project.updated_at else None,
        status=project.status,
        scan_count=scan_count or 0,
        subdomain_count=subdomain_count or 0,
        url_count=url_count or 0,
        vulnerability_count=vuln_count or 0,
    )


@router.put("/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: int,
    updates: ProjectUpdate,
    db: AsyncSession = Depends(get_db)
):
    """Update an existing project."""
    result = await db.execute(
        select(Project).where(Project.id == project_id)
    )
    project = result.scalar_one_or_none()
    
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )
    
    # Apply updates
    if updates.name is not None:
        project.name = updates.name
    if updates.target_domain is not None:
        project.target_domain = updates.target_domain
    if updates.description is not None:
        project.description = updates.description
    if updates.status is not None:
        project.status = updates.status
    
    await db.commit()
    await db.refresh(project)
    
    return ProjectResponse(
        id=project.id,
        name=project.name,
        target_domain=project.target_domain,
        description=project.description,
        created_at=project.created_at.isoformat() if project.created_at else None,
        updated_at=project.updated_at.isoformat() if project.updated_at else None,
        status=project.status,
    )


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(
    project_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Delete a project and all its data."""
    result = await db.execute(
        select(Project).where(Project.id == project_id)
    )
    project = result.scalar_one_or_none()
    
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )
    
    await db.delete(project)
    await db.commit()


@router.get("/{project_id}/stats", response_model=ProjectStats)
async def get_project_stats(
    project_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Get detailed statistics for a project."""
    # Verify project exists
    result = await db.execute(
        select(Project).where(Project.id == project_id)
    )
    project = result.scalar_one_or_none()
    
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )
    
    # Scan stats
    total_scans = await db.scalar(
        select(func.count(Scan.id)).where(Scan.project_id == project_id)
    ) or 0
    
    completed_scans = await db.scalar(
        select(func.count(Scan.id)).where(
            Scan.project_id == project_id,
            Scan.status == "completed"
        )
    ) or 0
    
    failed_scans = await db.scalar(
        select(func.count(Scan.id)).where(
            Scan.project_id == project_id,
            Scan.status == "failed"
        )
    ) or 0
    
    running_scans = await db.scalar(
        select(func.count(Scan.id)).where(
            Scan.project_id == project_id,
            Scan.status == "running"
        )
    ) or 0
    
    # Subdomain stats
    total_subdomains = await db.scalar(
        select(func.count(Subdomain.id)).where(Subdomain.project_id == project_id)
    ) or 0
    
    alive_subdomains = await db.scalar(
        select(func.count(Subdomain.id)).where(
            Subdomain.project_id == project_id,
            Subdomain.is_alive == True
        )
    ) or 0
    
    # URL stats
    total_urls = await db.scalar(
        select(func.count(URL.id)).where(URL.project_id == project_id)
    ) or 0
    
    urls_with_params = await db.scalar(
        select(func.count(URL.id)).where(
            URL.project_id == project_id,
            URL.has_params == True
        )
    ) or 0
    
    # Vulnerability stats
    total_vulns = await db.scalar(
        select(func.count(Vulnerability.id)).where(Vulnerability.project_id == project_id)
    ) or 0
    
    critical_vulns = await db.scalar(
        select(func.count(Vulnerability.id)).where(
            Vulnerability.project_id == project_id,
            Vulnerability.severity == "critical"
        )
    ) or 0
    
    high_vulns = await db.scalar(
        select(func.count(Vulnerability.id)).where(
            Vulnerability.project_id == project_id,
            Vulnerability.severity == "high"
        )
    ) or 0
    
    medium_vulns = await db.scalar(
        select(func.count(Vulnerability.id)).where(
            Vulnerability.project_id == project_id,
            Vulnerability.severity == "medium"
        )
    ) or 0
    
    low_vulns = await db.scalar(
        select(func.count(Vulnerability.id)).where(
            Vulnerability.project_id == project_id,
            Vulnerability.severity == "low"
        )
    ) or 0
    
    return ProjectStats(
        total_scans=total_scans,
        completed_scans=completed_scans,
        failed_scans=failed_scans,
        running_scans=running_scans,
        total_subdomains=total_subdomains,
        alive_subdomains=alive_subdomains,
        total_urls=total_urls,
        urls_with_params=urls_with_params,
        total_vulnerabilities=total_vulns,
        critical_vulns=critical_vulns,
        high_vulns=high_vulns,
        medium_vulns=medium_vulns,
        low_vulns=low_vulns,
    )
