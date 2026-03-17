"""
XSS Scanning Module

Automated Cross-Site Scripting vulnerability detection:
- Dalfox: Advanced XSS scanning with DOM analysis
- Kxss: Find reflected parameters
- Nuclei XSS templates

Returns list of potential XSS vulnerabilities with payloads.
"""

import asyncio
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Callable, Optional

from loguru import logger

from app.core.executor import executor
from app.utils.helpers import read_lines, write_lines


class XSSScanner:
    """
    XSS vulnerability scanner using multiple tools.
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
        Scan URLs for XSS vulnerabilities.
        
        Args:
            urls: List of URLs with parameters to test
            
        Returns:
            List of vulnerability dictionaries
        """
        self.work_dir.mkdir(parents=True, exist_ok=True)
        
        # Filter URLs that have parameters (most likely to have XSS)
        param_urls = [u for u in urls if "=" in u]
        
        if not param_urls:
            await self.log("[!] No URLs with parameters found for XSS testing")
            return []
        
        await self.log(f"[*] Testing {len(param_urls)} URLs for XSS...")
        
        # Write URLs to file
        input_file = self.work_dir / "xss_urls.txt"
        write_lines(input_file, param_urls)
        
        vulnerabilities = []
        
        # Run tools
        tasks = []
        
        if await executor.check_tool("dalfox"):
            tasks.append(self._run_dalfox(input_file))
        else:
            await self.log("[!] Dalfox not found")
        
        if await executor.check_tool("kxss"):
            tasks.append(self._run_kxss(input_file))
        
        if await executor.check_tool("nuclei"):
            tasks.append(self._run_nuclei_xss(input_file))
        
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, Exception):
                    await self.log(f"[!] Tool error: {str(result)}")
                elif isinstance(result, list):
                    vulnerabilities.extend(result)
        
        # Deduplicate by URL + parameter
        seen = set()
        unique_vulns = []
        for vuln in vulnerabilities:
            key = (vuln["url"], vuln.get("parameter", ""))
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)
        
        await self.log(f"[+] Found {len(unique_vulns)} potential XSS vulnerabilities")
        
        return unique_vulns
    
    async def _run_dalfox(self, input_file: Path) -> List[Dict[str, Any]]:
        """Run Dalfox XSS scanner."""
        await self.log("[*] Running Dalfox...")
        
        output_file = self.work_dir / "dalfox_output.json"
        
        result = await executor.run(
            "dalfox",
            [
                "file", str(input_file),
                "-o", str(output_file),
                "--format", "json",
                "--silence",
            ],
            timeout=1800,  # 30 minutes
        )
        
        vulnerabilities = []
        
        if output_file.exists():
            try:
                with open(output_file, 'r') as f:
                    for line in f:
                        try:
                            data = json.loads(line.strip())
                            
                            vulnerabilities.append({
                                "type": "xss",
                                "severity": self._classify_xss_severity(data),
                                "url": data.get("data", {}).get("url", ""),
                                "parameter": data.get("data", {}).get("param", ""),
                                "payload": data.get("data", {}).get("payload", ""),
                                "evidence": data.get("data", {}).get("evidence", ""),
                                "tool": "dalfox",
                            })
                        except json.JSONDecodeError:
                            continue
            except Exception as e:
                await self.log(f"[!] Error parsing Dalfox output: {e}")
        
        await self.log(f"[+] Dalfox found {len(vulnerabilities)} XSS")
        
        return vulnerabilities
    
    def _classify_xss_severity(self, data: dict) -> str:
        """Classify XSS severity based on type."""
        vuln_type = data.get("type", "").lower()
        
        if "stored" in vuln_type:
            return "critical"
        elif "dom" in vuln_type:
            return "high"
        elif "reflected" in vuln_type:
            return "high"
        else:
            return "medium"
    
    async def _run_kxss(self, input_file: Path) -> List[Dict[str, Any]]:
        """Run kxss to find reflected parameters."""
        await self.log("[*] Running kxss...")
        
        output_file = self.work_dir / "kxss_output.txt"
        
        # kxss reads from stdin
        urls = read_lines(input_file)
        input_data = "\n".join(urls)
        
        result = await executor.run_with_input(
            "kxss",
            [],
            input_data=input_data,
            timeout=600,
        )
        
        vulnerabilities = []
        
        if result.success:
            for line in result.stdout.splitlines():
                if line.strip():
                    # kxss output format varies, try to extract URL
                    url_match = re.search(r'https?://[^\s]+', line)
                    if url_match:
                        vulnerabilities.append({
                            "type": "xss",
                            "severity": "medium",
                            "url": url_match.group(0),
                            "evidence": line.strip(),
                            "tool": "kxss",
                        })
        
        await self.log(f"[+] kxss found {len(vulnerabilities)} reflected params")
        
        # Save output
        write_lines(output_file, [v["url"] for v in vulnerabilities])
        
        return vulnerabilities
    
    async def _run_nuclei_xss(self, input_file: Path) -> List[Dict[str, Any]]:
        """Run Nuclei with XSS templates."""
        await self.log("[*] Running Nuclei XSS templates...")
        
        output_file = self.work_dir / "nuclei_xss.json"
        
        result = await executor.run(
            "nuclei",
            [
                "-l", str(input_file),
                "-t", "http/vulnerabilities/xss/",
                "-t", "dast/vulnerabilities/xss/",
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
                        "type": "xss",
                        "severity": data.get("info", {}).get("severity", "medium"),
                        "url": data.get("matched-at", ""),
                        "template_id": data.get("template-id", ""),
                        "evidence": data.get("extracted-results", ""),
                        "tool": "nuclei",
                    })
                except json.JSONDecodeError:
                    continue
        
        await self.log(f"[+] Nuclei found {len(vulnerabilities)} XSS")
        
        return vulnerabilities
