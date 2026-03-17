"""
Results API Routes

Endpoints for retrieving scan results (subdomains, URLs, vulnerabilities).

Routes:
- GET /api/results/subdomains - List subdomains for a project
- GET /api/results/urls - List URLs for a project
- GET /api/results/vulnerabilities - List vulnerabilities for a project
- GET /api/results/export/{project_id} - Export all results
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
import json
import csv
import io

from app.database import get_db, Project, Subdomain, URL, Vulnerability


router = APIRouter(prefix="/api/results", tags=["results"])


# ===================
# Response Models
# ===================

class SubdomainResponse(BaseModel):
    """Subdomain result."""
    id: int
    subdomain: str
    source: Optional[str]
    is_alive: bool
    ip_address: Optional[str]
    status_code: Optional[int]
    title: Optional[str]
    tech_stack: List[str]
    cdn: Optional[str]
    takeover_vulnerable: bool
    
    class Config:
        from_attributes = True


class URLResponse(BaseModel):
    """URL result."""
    id: int
    url: str
    source: Optional[str]
    status_code: Optional[int]
    content_type: Optional[str]
    has_params: bool
    param_names: List[str]
    file_type: Optional[str]
    is_api: bool
    
    class Config:
        from_attributes = True


class VulnerabilityResponse(BaseModel):
    """Vulnerability result."""
    id: int
    vuln_type: str
    severity: str
    url: str
    parameter: Optional[str]
    payload: Optional[str]
    evidence: Optional[str]
    tool: Optional[str]
    template_id: Optional[str]
    verified: bool
    false_positive: bool
    notes: Optional[str]
    created_at: Optional[str]
    
    class Config:
        from_attributes = True


class PaginatedResponse(BaseModel):
    """Paginated response wrapper."""
    items: List
    total: int
    page: int
    page_size: int
    pages: int


# ===================
# Endpoints
# ===================

@router.get("/subdomains")
async def list_subdomains(
    project_id: int,
    alive_only: bool = False,
    search: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db)
):
    """
    List subdomains for a project.
    
    - **project_id**: Required project ID
    - **alive_only**: Only return subdomains that responded to HTTP
    - **search**: Filter by subdomain name
    - **page**: Page number
    - **page_size**: Items per page
    """
    # Verify project exists
    project_check = await db.execute(
        select(Project.id).where(Project.id == project_id)
    )
    if not project_check.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Build query
    query = select(Subdomain).where(Subdomain.project_id == project_id)
    
    if alive_only:
        query = query.where(Subdomain.is_alive == True)
    
    if search:
        query = query.where(Subdomain.subdomain.ilike(f"%{search}%"))
    
    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total = await db.scalar(count_query) or 0
    
    # Apply pagination
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size).order_by(Subdomain.subdomain)
    
    result = await db.execute(query)
    subdomains = result.scalars().all()
    
    items = [
        SubdomainResponse(
            id=s.id,
            subdomain=s.subdomain,
            source=s.source,
            is_alive=s.is_alive,
            ip_address=s.ip_address,
            status_code=s.status_code,
            title=s.title,
            tech_stack=s.tech_stack or [],
            cdn=s.cdn,
            takeover_vulnerable=s.takeover_vulnerable,
        )
        for s in subdomains
    ]
    
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size,
    }


@router.get("/urls")
async def list_urls(
    project_id: int,
    has_params: Optional[bool] = None,
    is_api: Optional[bool] = None,
    file_type: Optional[str] = None,
    search: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db)
):
    """
    List URLs for a project.
    
    - **project_id**: Required project ID
    - **has_params**: Filter URLs with/without parameters
    - **is_api**: Filter API endpoints
    - **file_type**: Filter by file type (js, json, xml, etc.)
    - **search**: Search in URL
    """
    # Verify project exists
    project_check = await db.execute(
        select(Project.id).where(Project.id == project_id)
    )
    if not project_check.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Build query
    query = select(URL).where(URL.project_id == project_id)
    
    if has_params is not None:
        query = query.where(URL.has_params == has_params)
    
    if is_api is not None:
        query = query.where(URL.is_api == is_api)
    
    if file_type:
        query = query.where(URL.file_type == file_type)
    
    if search:
        query = query.where(URL.url.ilike(f"%{search}%"))
    
    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total = await db.scalar(count_query) or 0
    
    # Apply pagination
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)
    
    result = await db.execute(query)
    urls = result.scalars().all()
    
    items = [
        URLResponse(
            id=u.id,
            url=u.url,
            source=u.source,
            status_code=u.status_code,
            content_type=u.content_type,
            has_params=u.has_params,
            param_names=u.param_names or [],
            file_type=u.file_type,
            is_api=u.is_api,
        )
        for u in urls
    ]
    
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size,
    }


@router.get("/vulnerabilities")
async def list_vulnerabilities(
    project_id: int,
    severity: Optional[str] = None,
    vuln_type: Optional[str] = None,
    verified_only: bool = False,
    exclude_false_positives: bool = True,
    search: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db)
):
    """
    List vulnerabilities for a project.
    
    - **project_id**: Required project ID
    - **severity**: Filter by severity (critical, high, medium, low, info)
    - **vuln_type**: Filter by type (xss, sqli, ssrf, etc.)
    - **verified_only**: Only show manually verified vulnerabilities
    - **exclude_false_positives**: Hide false positives (default: true)
    """
    # Verify project exists
    project_check = await db.execute(
        select(Project.id).where(Project.id == project_id)
    )
    if not project_check.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Build query
    query = select(Vulnerability).where(Vulnerability.project_id == project_id)
    
    if severity:
        query = query.where(Vulnerability.severity == severity)
    
    if vuln_type:
        query = query.where(Vulnerability.vuln_type == vuln_type)
    
    if verified_only:
        query = query.where(Vulnerability.verified == True)
    
    if exclude_false_positives:
        query = query.where(Vulnerability.false_positive == False)
    
    if search:
        query = query.where(Vulnerability.url.ilike(f"%{search}%"))
    
    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total = await db.scalar(count_query) or 0
    
    # Apply pagination  
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size).order_by(
        # Sort by severity (critical first)
        Vulnerability.severity,
        Vulnerability.created_at.desc()
    )
    
    result = await db.execute(query)
    vulns = result.scalars().all()
    
    items = [
        VulnerabilityResponse(
            id=v.id,
            vuln_type=v.vuln_type,
            severity=v.severity,
            url=v.url,
            parameter=v.parameter,
            payload=v.payload,
            evidence=v.evidence,
            tool=v.tool,
            template_id=v.template_id,
            verified=v.verified,
            false_positive=v.false_positive,
            notes=v.notes,
            created_at=v.created_at.isoformat() if v.created_at else None,
        )
        for v in vulns
    ]
    
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size,
    }


@router.patch("/vulnerabilities/{vuln_id}")
async def update_vulnerability(
    vuln_id: int,
    verified: Optional[bool] = None,
    false_positive: Optional[bool] = None,
    notes: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Update a vulnerability (mark as verified, false positive, add notes).
    """
    result = await db.execute(
        select(Vulnerability).where(Vulnerability.id == vuln_id)
    )
    vuln = result.scalar_one_or_none()
    
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    
    if verified is not None:
        vuln.verified = verified
    if false_positive is not None:
        vuln.false_positive = false_positive
    if notes is not None:
        vuln.notes = notes
    
    await db.commit()
    
    return {"message": "Vulnerability updated", "id": vuln_id}


@router.get("/export/{project_id}")
async def export_results(
    project_id: int,
    format: str = Query("json", regex="^(json|csv)$"),
    db: AsyncSession = Depends(get_db)
):
    """
    Export all results for a project.
    
    - **format**: Export format (json or csv)
    """
    # Verify project exists
    project_result = await db.execute(
        select(Project).where(Project.id == project_id)
    )
    project = project_result.scalar_one_or_none()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Get all data
    subdomains_result = await db.execute(
        select(Subdomain).where(Subdomain.project_id == project_id)
    )
    subdomains = subdomains_result.scalars().all()
    
    urls_result = await db.execute(
        select(URL).where(URL.project_id == project_id)
    )
    urls = urls_result.scalars().all()
    
    vulns_result = await db.execute(
        select(Vulnerability).where(Vulnerability.project_id == project_id)
    )
    vulns = vulns_result.scalars().all()
    
    if format == "json":
        # JSON export
        data = {
            "project": {
                "id": project.id,
                "name": project.name,
                "target_domain": project.target_domain,
                "description": project.description,
            },
            "subdomains": [s.to_dict() for s in subdomains],
            "urls": [u.to_dict() for u in urls],
            "vulnerabilities": [v.to_dict() for v in vulns],
        }
        
        return StreamingResponse(
            io.BytesIO(json.dumps(data, indent=2).encode()),
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{project.target_domain}_results.json"'
            }
        )
    
    else:
        # CSV export - create multiple sheets in a ZIP or just vulnerabilities
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write vulnerabilities
        writer.writerow([
            "ID", "Type", "Severity", "URL", "Parameter", "Payload",
            "Tool", "Template ID", "Verified", "False Positive", "Notes"
        ])
        
        for v in vulns:
            writer.writerow([
                v.id, v.vuln_type, v.severity, v.url, v.parameter,
                v.payload, v.tool, v.template_id, v.verified,
                v.false_positive, v.notes
            ])
        
        output.seek(0)
        
        return StreamingResponse(
            io.BytesIO(output.getvalue().encode()),
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="{project.target_domain}_vulnerabilities.csv"'
            }
        )
