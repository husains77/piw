"""
SSRF (Server-Side Request Forgery) Testing Module

Tests for SSRF vulnerabilities using:
- Nuclei SSRF templates
- Manual payload injection testing

Note: Full SSRF testing requires a callback server (like Interactsh)
to detect out-of-band interactions.
"""

import asyncio
import json
from pathlib import Path
from typing import List, Dict, Any, Callable, Optional

from loguru import logger

from app.core.executor import executor
from app.utils.helpers import read_lines, write_lines


class SSRFScanner:
    """
    SSRF vulnerability scanner.
    """
    
    def __init__(
        self,
        work_dir: Path,
        log_callback: Optional[Callable] = None
    ):
        self.work_dir = work_dir
        self.log = log_callback or self._default_log
    
    async def _default_log(self, msg: str):
        logger.info(msg)
    
    async def run(self, urls: List[str]) -> List[Dict[str, Any]]:
        """
        Scan URLs for SSRF vulnerabilities.
        
        Args:
            urls: List of URLs with parameters
            
        Returns:
            List of vulnerability dictionaries
        """
        self.work_dir.mkdir(parents=True, exist_ok=True)
        
        # Filter URLs with URL-like parameters
        ssrf_candidates = []
        for url in urls:
            lower = url.lower()
            if any(param in lower for param in [
                "url=", "uri=", "path=", "dest=", "redirect=",
                "site=", "html=", "img=", "load=", "request=",
                "fetch=", "proxy=", "link=", "href=", "return=",
                "next=", "data=", "reference=", "callback=",
            ]):
                ssrf_candidates.append(url)
        
        if not ssrf_candidates:
            await self.log("[!] No SSRF candidate URLs found")
            return []
        
        await self.log(f"[*] Testing {len(ssrf_candidates)} URLs for SSRF...")
        
        input_file = self.work_dir / "ssrf_urls.txt"
        write_lines(input_file, ssrf_candidates)
        
        vulnerabilities = []
        
        # Run Nuclei SSRF templates
        if await executor.check_tool("nuclei"):
            nuclei_vulns = await self._run_nuclei_ssrf(input_file)
            vulnerabilities.extend(nuclei_vulns)
        
        await self.log(f"[+] Found {len(vulnerabilities)} SSRF vulnerabilities")
        
        return vulnerabilities
    
    async def _run_nuclei_ssrf(self, input_file: Path) -> List[Dict[str, Any]]:
        """Run Nuclei with SSRF templates."""
        await self.log("[*] Running Nuclei SSRF templates...")
        
        output_file = self.work_dir / "nuclei_ssrf.json"
        
        result = await executor.run(
            "nuclei",
            [
                "-l", str(input_file),
                "-t", "http/vulnerabilities/ssrf/",
                "-t", "dast/vulnerabilities/ssrf/",
                "-jsonl",
                "-o", str(output_file),
            ],
            timeout=1200,
        )
        
        vulnerabilities = []
        
        if output_file.exists():
            for line in read_lines(output_file):
                try:
                    data = json.loads(line)
                    
                    vulnerabilities.append({
                        "type": "ssrf",
                        "severity": data.get("info", {}).get("severity", "high"),
                        "url": data.get("matched-at", ""),
                        "template_id": data.get("template-id", ""),
                        "evidence": str(data.get("extracted-results", "")),
                        "tool": "nuclei",
                    })
                except json.JSONDecodeError:
                    continue
        
        await self.log(f"[+] Nuclei found {len(vulnerabilities)} SSRF")
        
        return vulnerabilities
