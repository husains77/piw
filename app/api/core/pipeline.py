"""
Recon Pipeline Orchestration

This module coordinates the execution of reconnaissance scans.

The pipeline:
1. Receives a scan request (scan type, project, config)
2. Determines which tools to run
3. Executes tools in sequence or parallel as appropriate
4. Streams output via WebSocket
5. Saves results to database
6. Updates scan status

Supports running individual scan types or the full pipeline.
"""

import asyncio
from datetime import datetime
from typing import Dict, Any, Callable, Optional
from pathlib import Path

from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import (
    AsyncSessionLocal, Scan, Project, Subdomain, URL, Vulnerability,
    ScanStatus
)
from app.config import settings
from app.core.executor import executor
from app.api.routes.websocket import send_scan_update


class ScanPipeline:
    """
    Orchestrates the execution of reconnaissance scans.
    
    Each scan type maps to one or more tools that are executed
    in sequence or parallel.
    """
    
    def __init__(self, scan_id: int, domain: str, scan_type: str, config: Dict[str, Any]):
        """
        Initialize the pipeline.
        
        Args:
            scan_id: Database ID of the scan
            domain: Target domain
            scan_type: Type of scan to run
            config: Additional configuration options
        """
        self.scan_id = scan_id
        self.domain = domain
        self.scan_type = scan_type
        self.config = config
        self.work_dir: Optional[Path] = None
        self.db: Optional[AsyncSession] = None
        self._db_lock = asyncio.Lock()
    
    async def log(self, message: str):
        """Log a message and send to WebSocket."""
        # Use local time instead of UTC
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_line = f"[{timestamp}] {message}"
        logger.info(f"[Scan {self.scan_id}] {message}")
        
        # Send to WebSocket
        await send_scan_update(self.scan_id, "log", {"message": log_line})
        
        # Update database log with lock
        if self.db:
            async with self._db_lock:
                try:
                    result = await self.db.execute(
                        select(Scan).where(Scan.id == self.scan_id)
                    )
                    scan = result.scalar_one_or_none()
                    if scan:
                        # Append to existing logs
                        current_logs = scan.log_output or ""
                        # Avoid growing too large in memory if possible, but for now simple append
                        scan.log_output = current_logs + log_line + "\n"
                        await self.db.commit()
                except Exception as e:
                    logger.error(f"Failed to save log to DB: {e}")
                    # Don't raise, just log error so scan continues

    
    async def update_status(self, status: str, items_found: int = 0, error: str = None):
        """Update scan status in database."""
        if self.db:
            async with self._db_lock:
                try:
                    result = await self.db.execute(
                        select(Scan).where(Scan.id == self.scan_id)
                    )
                    scan = result.scalar_one_or_none()
                    if scan:
                        scan.status = status
                        scan.items_found = items_found
                        if error:
                            scan.error_message = error
                        if status == ScanStatus.RUNNING.value and not scan.started_at:
                            scan.started_at = datetime.now()
                        if status in [ScanStatus.COMPLETED.value, ScanStatus.FAILED.value]:
                            scan.completed_at = datetime.now()
                        await self.db.commit()
                except Exception as e:
                    logger.error(f"Failed to update status in DB: {e}")

        
        # Send status update via WebSocket
        await send_scan_update(self.scan_id, "status", {
            "status": status,
            "items_found": items_found,
            "error": error
        })
    
    async def run(self):
        """
        Execute the scan pipeline.
        
        This is the main entry point called by the background task.
        """
        async with AsyncSessionLocal() as db:
            self.db = db
            
            try:
                # Get project info
                scan_result = await db.execute(
                    select(Scan).where(Scan.id == self.scan_id)
                )
                scan = scan_result.scalar_one_or_none()
                
                if not scan:
                    logger.error(f"Scan {self.scan_id} not found")
                    return
                
                project_result = await db.execute(
                    select(Project).where(Project.id == scan.project_id)
                )
                project = project_result.scalar_one_or_none()
                
                if not project:
                    await self.update_status(ScanStatus.FAILED.value, error="Project not found")
                    return
                
                # Set up work directory
                self.work_dir = settings.get_scan_dir(project.id, self.scan_id)
                
                # Update status to running
                await self.update_status(ScanStatus.RUNNING.value)
                await self.log(f"Starting {self.scan_type} scan for {self.domain}")
                
                # Import modules here to avoid circular imports
                from app.modules import subdomain, alive, urls, xss, sqli, ssrf, lfi, fuzzing, nuclei, javascript, api_testing, cloud
                
                # Route to appropriate scan module
                scan_handlers = {
                    "subdomain": self._run_subdomain,
                    "alive": self._run_alive,
                    "urls": self._run_urls,
                    "xss": self._run_xss,
                    "sqli": self._run_sqli,
                    "ssrf": self._run_ssrf,
                    "lfi": self._run_lfi,
                    "fuzzing": self._run_fuzzing,
                    "nuclei": self._run_nuclei,
                    "javascript": self._run_javascript,
                    "api": self._run_api,
                    "cloud": self._run_cloud,
                    "full": self._run_full_pipeline,
                }
                
                handler = scan_handlers.get(self.scan_type)
                
                if not handler:
                    await self.update_status(
                        ScanStatus.FAILED.value,
                        error=f"Unknown scan type: {self.scan_type}"
                    )
                    return
                
                # Run the scan
                items_found = await handler()
                
                # Mark as complete
                await self.update_status(ScanStatus.COMPLETED.value, items_found=items_found)
                await self.log(f"Scan completed. Found {items_found} items.")
                
            except asyncio.CancelledError:
                await self.log("Scan cancelled by user")
                await self.update_status(ScanStatus.CANCELLED.value)
                raise
                
            except Exception as e:
                logger.exception(f"Scan {self.scan_id} failed")
                await self.log(f"Error: {str(e)}")
                await self.update_status(ScanStatus.FAILED.value, error=str(e))
    
    async def _run_subdomain(self) -> int:
        """Run subdomain enumeration."""
        from app.modules.subdomain import SubdomainScanner
        
        scanner = SubdomainScanner(
            domain=self.domain,
            work_dir=self.work_dir,
            log_callback=self.log
        )
        
        subdomains = await scanner.run()
        
        # Save to database
        if self.db:
            scan_result = await self.db.execute(
                select(Scan).where(Scan.id == self.scan_id)
            )
            scan = scan_result.scalar_one_or_none()
            project_id = scan.project_id if scan else None
            
            if project_id:
                for sub_data in subdomains:
                    # Check if exists
                    existing = await self.db.execute(
                        select(Subdomain).where(
                            Subdomain.project_id == project_id,
                            Subdomain.subdomain == sub_data["subdomain"]
                        )
                    )
                    if not existing.scalar_one_or_none():
                        subdomain = Subdomain(
                            project_id=project_id,
                            subdomain=sub_data["subdomain"],
                            source=sub_data.get("source"),
                        )
                        self.db.add(subdomain)
                
                await self.db.commit()
        
        return len(subdomains)
    
    async def _run_alive(self) -> int:
        """Run alive checking."""
        from app.modules.alive import AliveChecker
        
        # Get subdomains from database
        if not self.db:
            return 0
        
        scan_result = await self.db.execute(
            select(Scan).where(Scan.id == self.scan_id)
        )
        scan = scan_result.scalar_one_or_none()
        
        if not scan:
            return 0
        
        subs_result = await self.db.execute(
            select(Subdomain).where(Subdomain.project_id == scan.project_id)
        )
        subdomains = [s.subdomain for s in subs_result.scalars().all()]
        
        if not subdomains:
            await self.log("No subdomains found. Run subdomain scan first.")
            return 0
        
        checker = AliveChecker(
            work_dir=self.work_dir,
            log_callback=self.log
        )
        
        results = await checker.run(subdomains)
        
        # Update database
        for result in results:
            update_result = await self.db.execute(
                select(Subdomain).where(
                    Subdomain.project_id == scan.project_id,
                    Subdomain.subdomain == result["subdomain"]
                )
            )
            subdomain = update_result.scalar_one_or_none()
            
            if subdomain:
                subdomain.is_alive = result.get("is_alive", False)
                subdomain.ip_address = result.get("ip")
                subdomain.status_code = result.get("status_code")
                subdomain.title = result.get("title")
                subdomain.tech_stack = result.get("tech_stack", [])
                subdomain.cdn = result.get("cdn")
        
        await self.db.commit()
        
        return len([r for r in results if r.get("is_alive")])
    
    async def _run_urls(self) -> int:
        """Run URL collection."""
        from app.modules.urls import URLCollector
        
        if not self.db:
            return 0
        
        scan_result = await self.db.execute(
            select(Scan).where(Scan.id == self.scan_id)
        )
        scan = scan_result.scalar_one_or_none()
        
        if not scan:
            return 0
        
        # Get alive subdomains
        subs_result = await self.db.execute(
            select(Subdomain).where(
                Subdomain.project_id == scan.project_id,
                Subdomain.is_alive == True
            )
        )
        subdomains = [s.subdomain for s in subs_result.scalars().all()]
        
        if not subdomains:
            await self.log("No alive subdomains found. Run alive check first.")
            return 0
        
        collector = URLCollector(
            work_dir=self.work_dir,
            log_callback=self.log
        )
        
        urls = await collector.run(subdomains)
        
        # Save to database
        for url_data in urls:
            existing = await self.db.execute(
                select(URL).where(
                    URL.project_id == scan.project_id,
                    URL.url == url_data["url"]
                )
            )
            if not existing.scalar_one_or_none():
                url = URL(
                    project_id=scan.project_id,
                    url=url_data["url"],
                    source=url_data.get("source"),
                    has_params=url_data.get("has_params", False),
                    param_names=url_data.get("param_names", []),
                    file_type=url_data.get("file_type"),
                    is_api=url_data.get("is_api", False),
                )
                self.db.add(url)
        
        await self.db.commit()
        
        return len(urls)
    
    async def _run_xss(self) -> int:
        """Run XSS scanning."""
        from app.modules.xss import XSSScanner
        
        return await self._run_vuln_scan(XSSScanner)
    
    async def _run_sqli(self) -> int:
        """Run SQL injection scanning."""
        from app.modules.sqli import SQLiScanner
        
        return await self._run_vuln_scan(SQLiScanner)
    
    async def _run_ssrf(self) -> int:
        """Run SSRF testing."""
        from app.modules.ssrf import SSRFScanner
        
        return await self._run_vuln_scan(SSRFScanner)
    
    async def _run_lfi(self) -> int:
        """Run LFI testing."""
        from app.modules.lfi import LFIScanner
        
        return await self._run_vuln_scan(LFIScanner)
    
    async def _run_vuln_scan(self, scanner_class) -> int:
        """Generic vulnerability scan runner."""
        if not self.db:
            return 0
        
        scan_result = await self.db.execute(
            select(Scan).where(Scan.id == self.scan_id)
        )
        scan = scan_result.scalar_one_or_none()
        
        if not scan:
            return 0
        
        # Get URLs with parameters
        urls_result = await self.db.execute(
            select(URL).where(
                URL.project_id == scan.project_id,
                URL.has_params == True
            )
        )
        urls = [u.url for u in urls_result.scalars().all()]
        
        if not urls:
            await self.log("No URLs with parameters found. Run URL collection first.")
            return 0
        
        scanner = scanner_class(
            work_dir=self.work_dir,
            log_callback=self.log
        )
        
        vulns = await scanner.run(urls)
        
        # Save vulnerabilities
        for vuln_data in vulns:
            vuln = Vulnerability(
                project_id=scan.project_id,
                scan_id=self.scan_id,
                vuln_type=vuln_data["type"],
                severity=vuln_data.get("severity", "medium"),
                url=vuln_data["url"],
                parameter=vuln_data.get("parameter"),
                payload=vuln_data.get("payload"),
                evidence=vuln_data.get("evidence"),
                tool=vuln_data.get("tool"),
                template_id=vuln_data.get("template_id"),
            )
            self.db.add(vuln)
        
        await self.db.commit()
        
        return len(vulns)
    
    async def _run_fuzzing(self) -> int:
        """Run directory fuzzing."""
        from app.modules.fuzzing import FuzzingScanner
        
        if not self.db:
            return 0
        
        scan_result = await self.db.execute(
            select(Scan).where(Scan.id == self.scan_id)
        )
        scan = scan_result.scalar_one_or_none()
        
        if not scan:
            return 0
        
        # Get alive subdomains
        subs_result = await self.db.execute(
            select(Subdomain).where(
                Subdomain.project_id == scan.project_id,
                Subdomain.is_alive == True
            )
        )
        targets = [f"https://{s.subdomain}" for s in subs_result.scalars().all()]
        
        if not targets:
            await self.log("No alive subdomains found.")
            return 0
        
        scanner = FuzzingScanner(
            work_dir=self.work_dir,
            log_callback=self.log
        )
        
        results = await scanner.run(targets[:10])  # Limit to first 10
        
        # Save discovered URLs
        for url_data in results:
            existing = await self.db.execute(
                select(URL).where(
                    URL.project_id == scan.project_id,
                    URL.url == url_data["url"]
                )
            )
            if not existing.scalar_one_or_none():
                url = URL(
                    project_id=scan.project_id,
                    url=url_data["url"],
                    source="fuzzing",
                    status_code=url_data.get("status_code"),
                )
                self.db.add(url)
        
        await self.db.commit()
        
        return len(results)
    
    async def _run_nuclei(self) -> int:
        """Run Nuclei scanning."""
        from app.modules.nuclei import NucleiScanner
        
        if not self.db:
            return 0
        
        scan_result = await self.db.execute(
            select(Scan).where(Scan.id == self.scan_id)
        )
        scan = scan_result.scalar_one_or_none()
        
        if not scan:
            return 0
        
        # Get alive subdomains
        subs_result = await self.db.execute(
            select(Subdomain).where(
                Subdomain.project_id == scan.project_id,
                Subdomain.is_alive == True
            )
        )
        targets = [s.subdomain for s in subs_result.scalars().all()]
        
        if not targets:
            await self.log("No alive subdomains found.")
            return 0
        
        scanner = NucleiScanner(
            work_dir=self.work_dir,
            log_callback=self.log
        )
        
        vulns = await scanner.run(targets)
        
        # Save vulnerabilities
        for vuln_data in vulns:
            vuln = Vulnerability(
                project_id=scan.project_id,
                scan_id=self.scan_id,
                vuln_type=vuln_data.get("type", "nuclei"),
                severity=vuln_data.get("severity", "info"),
                url=vuln_data["url"],
                template_id=vuln_data.get("template_id"),
                evidence=vuln_data.get("evidence"),
                tool="nuclei",
            )
            self.db.add(vuln)
        
        await self.db.commit()
        
        return len(vulns)
    
    async def _run_javascript(self) -> int:
        """Run JavaScript analysis."""
        from app.modules.javascript import JavaScriptAnalyzer
        
        if not self.db:
            return 0
        
        scan_result = await self.db.execute(
            select(Scan).where(Scan.id == self.scan_id)
        )
        scan = scan_result.scalar_one_or_none()
        
        if not scan:
            return 0
        
        # Get JS URLs
        urls_result = await self.db.execute(
            select(URL).where(
                URL.project_id == scan.project_id,
                URL.file_type == "js"
            )
        )
        js_urls = [u.url for u in urls_result.scalars().all()]
        
        if not js_urls:
            await self.log("No JavaScript files found.")
            return 0
        
        analyzer = JavaScriptAnalyzer(
            work_dir=self.work_dir,
            log_callback=self.log
        )
        
        results = await analyzer.run(js_urls)
        
        # Save found secrets as vulnerabilities
        for result in results.get("secrets", []):
            vuln = Vulnerability(
                project_id=scan.project_id,
                scan_id=self.scan_id,
                vuln_type="secret_disclosure",
                severity="high",
                url=result["url"],
                evidence=result.get("secret"),
                tool="secretfinder",
            )
            self.db.add(vuln)
        
        await self.db.commit()
        
        return len(results.get("secrets", []))
    
    async def _run_api(self) -> int:
        """Run API testing."""
        from app.modules.api_testing import APITester
        
        if not self.db:
            return 0
        
        scan_result = await self.db.execute(
            select(Scan).where(Scan.id == self.scan_id)
        )
        scan = scan_result.scalar_one_or_none()
        
        if not scan:
            return 0
        
        # Get API URLs
        urls_result = await self.db.execute(
            select(URL).where(
                URL.project_id == scan.project_id,
                URL.is_api == True
            )
        )
        api_urls = [u.url for u in urls_result.scalars().all()]
        
        if not api_urls:
            await self.log("No API endpoints found.")
            return 0
        
        tester = APITester(
            work_dir=self.work_dir,
            log_callback=self.log
        )
        
        results = await tester.run(api_urls)
        
        return len(results)
    
    async def _run_cloud(self) -> int:
        """Run cloud storage testing."""
        from app.modules.cloud import CloudScanner
        
        scanner = CloudScanner(
            work_dir=self.work_dir,
            log_callback=self.log
        )
        
        results = await scanner.run(self.domain)
        
        # Save findings as vulnerabilities
        if self.db:
            scan_result = await self.db.execute(
                select(Scan).where(Scan.id == self.scan_id)
            )
            scan = scan_result.scalar_one_or_none()
            
            if scan:
                for result in results:
                    vuln = Vulnerability(
                        project_id=scan.project_id,
                        scan_id=self.scan_id,
                        vuln_type="cloud_misconfiguration",
                        severity=result.get("severity", "medium"),
                        url=result.get("bucket"),
                        evidence=result.get("details"),
                        tool="s3scanner",
                    )
                    self.db.add(vuln)
                
                await self.db.commit()
        
        return len(results)
    
    async def _run_full_pipeline(self) -> int:
        """Run the complete recon pipeline."""
        total_items = 0
        
        await self.log("=== Starting Full Recon Pipeline ===")
        
        # 1. Subdomain enumeration
        await self.log("--- Phase 1: Subdomain Enumeration ---")
        subdomain_count = await self._run_subdomain()
        total_items += subdomain_count
        await self.log(f"Found {subdomain_count} subdomains")
        
        # 2. Alive checking
        await self.log("--- Phase 2: Alive Checking ---")
        alive_count = await self._run_alive()
        await self.log(f"Found {alive_count} alive subdomains")
        
        # 3. URL collection
        await self.log("--- Phase 3: URL Collection ---")
        url_count = await self._run_urls()
        total_items += url_count
        await self.log(f"Collected {url_count} URLs")
        
        # 4. Nuclei scan
        await self.log("--- Phase 4: Nuclei Vulnerability Scan ---")
        nuclei_count = await self._run_nuclei()
        total_items += nuclei_count
        
        # 5. XSS scan
        await self.log("--- Phase 5: XSS Scanning ---")
        xss_count = await self._run_xss()
        total_items += xss_count
        
        # 6. SQLi scan (if URLs available)
        await self.log("--- Phase 6: SQL Injection Scanning ---")
        sqli_count = await self._run_sqli()
        total_items += sqli_count
        
        await self.log("=== Full Pipeline Complete ===")
        
        return total_items


async def run_scan_pipeline(scan_id: int, domain: str, scan_type: str, config: Dict[str, Any]):
    """
    Entry point for background scan execution.
    
    Called by FastAPI background tasks.
    """
    pipeline = ScanPipeline(scan_id, domain, scan_type, config)
    await pipeline.run()
