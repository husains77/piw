"""
SQL Injection Scanning Module

Automated SQLi vulnerability detection:
- SQLMap: Full-featured SQL injection testing
- Ghauri: Fast SQLi detection
- Nuclei SQLi templates

Returns list of SQL injection vulnerabilities.
"""

import asyncio
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Callable, Optional

from loguru import logger

from app.core.executor import executor
from app.utils.helpers import read_lines, write_lines


class SQLiScanner:
    """
    SQL Injection vulnerability scanner.
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
        Scan URLs for SQL injection.
        
        Args:
            urls: List of URLs with parameters
            
        Returns:
            List of vulnerability dictionaries
        """
        self.work_dir.mkdir(parents=True, exist_ok=True)
        
        # Filter URLs with parameters
        param_urls = [u for u in urls if "=" in u]
        
        if not param_urls:
            await self.log("[!] No URLs with parameters for SQLi testing")
            return []
        
        await self.log(f"[*] Testing {len(param_urls)} URLs for SQLi...")
        
        input_file = self.work_dir / "sqli_urls.txt"
        write_lines(input_file, param_urls[:100])  # Limit for safety
        
        vulnerabilities = []
        
        # Run tools
        tasks = []
        
        if await executor.check_tool("ghauri"):
            tasks.append(self._run_ghauri(param_urls[:20]))
        
        if await executor.check_tool("nuclei"):
            tasks.append(self._run_nuclei_sqli(input_file))
        
        # SQLMap is slower, run on fewer URLs
        if await executor.check_tool("sqlmap"):
            tasks.append(self._run_sqlmap(param_urls[:10]))
        
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, Exception):
                    await self.log(f"[!] Tool error: {str(result)}")
                elif isinstance(result, list):
                    vulnerabilities.extend(result)
        
        await self.log(f"[+] Found {len(vulnerabilities)} SQL injection vulnerabilities")
        
        return vulnerabilities
    
    async def _run_sqlmap(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Run SQLMap on URLs."""
        await self.log("[*] Running SQLMap (batch mode)...")
        
        vulnerabilities = []
        output_dir = self.work_dir / "sqlmap_output"
        output_dir.mkdir(exist_ok=True)
        
        for i, url in enumerate(urls):
            await self.log(f"    Testing URL {i+1}/{len(urls)}")
            
            result = await executor.run(
                "sqlmap",
                [
                    "-u", url,
                    "--batch",              # Non-interactive
                    "--random-agent",       # Random User-Agent
                    "--level", "2",         # Test level
                    "--risk", "2",          # Risk level
                    "--output-dir", str(output_dir),
                    "--smart",              # Smart mode
                ],
                timeout=300,  # 5 min per URL
            )
            
            # Check for vulnerabilities in output
            if result.success and "injectable" in result.stdout.lower():
                # Parse parameter from output
                param_match = re.search(r"Parameter: (\w+)", result.stdout)
                param = param_match.group(1) if param_match else None
                
                # Parse injection type
                type_match = re.search(r"Type: ([^\n]+)", result.stdout)
                injection_type = type_match.group(1) if type_match else "Unknown"
                
                vulnerabilities.append({
                    "type": "sqli",
                    "severity": "critical",
                    "url": url,
                    "parameter": param,
                    "payload": injection_type,
                    "evidence": "SQLMap confirmed injection",
                    "tool": "sqlmap",
                })
        
        await self.log(f"[+] SQLMap found {len(vulnerabilities)} SQLi")
        
        return vulnerabilities
    
    async def _run_ghauri(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Run Ghauri for fast SQLi detection."""
        await self.log("[*] Running Ghauri...")
        
        vulnerabilities = []
        
        for url in urls:
            result = await executor.run(
                "ghauri",
                ["-u", url, "--batch"],
                timeout=180,
            )
            
            if result.success and "vulnerable" in result.stdout.lower():
                # Extract parameter
                param_match = re.search(r"Parameter: (\w+)", result.stdout)
                param = param_match.group(1) if param_match else None
                
                vulnerabilities.append({
                    "type": "sqli",
                    "severity": "critical",
                    "url": url,
                    "parameter": param,
                    "evidence": "Ghauri confirmed injection",
                    "tool": "ghauri",
                })
        
        await self.log(f"[+] Ghauri found {len(vulnerabilities)} SQLi")
        
        return vulnerabilities
    
    async def _run_nuclei_sqli(self, input_file: Path) -> List[Dict[str, Any]]:
        """Run Nuclei with SQLi templates."""
        await self.log("[*] Running Nuclei SQLi templates...")
        
        output_file = self.work_dir / "nuclei_sqli.json"
        
        result = await executor.run(
            "nuclei",
            [
                "-l", str(input_file),
                "-t", "http/vulnerabilities/sqli/",
                "-t", "dast/vulnerabilities/sqli/",
                "-jsonl",
                "-o", str(output_file),
            ],
            timeout=1800,
        )
        
        vulnerabilities = []
        
        if output_file.exists():
            for line in read_lines(output_file):
                try:
                    data = json.loads(line)
                    
                    vulnerabilities.append({
                        "type": "sqli",
                        "severity": data.get("info", {}).get("severity", "high"),
                        "url": data.get("matched-at", ""),
                        "template_id": data.get("template-id", ""),
                        "evidence": str(data.get("extracted-results", "")),
                        "tool": "nuclei",
                    })
                except json.JSONDecodeError:
                    continue
        
        await self.log(f"[+] Nuclei found {len(vulnerabilities)} SQLi")
        
        return vulnerabilities
