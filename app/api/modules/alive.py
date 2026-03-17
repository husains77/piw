"""
Alive Checking Module

Checks which subdomains are reachable and gathers information:
- HTTPx: HTTP probing with status codes, titles, tech detection
- DNSX: DNS resolution for IP addresses
- Naabu: Port scanning

Returns enriched subdomain data with status, IPs, and technologies.
"""

import asyncio
import re
import json
from pathlib import Path
from typing import List, Dict, Any, Callable, Optional

from loguru import logger

from app.core.executor import executor
from app.utils.helpers import read_lines, write_lines
from app.config import settings


class AliveChecker:
    """
    Check subdomain availability and gather information.
    """
    
    def __init__(
        self,
        work_dir: Path,
        log_callback: Optional[Callable] = None
    ):
        """
        Initialize the checker.
        
        Args:
            work_dir: Directory for output files
            log_callback: Async function for logging
        """
        self.work_dir = work_dir
        self.log = log_callback or self._default_log
    
    async def _default_log(self, msg: str):
        logger.info(msg)

    async def _print_progress(self, line: str):
        """Format and print progress to console."""
        # Simple color formatting (if not already colored)
        if "[*]" in line:
            print(f"\033[34m{line}\033[0m") # Blue
        elif "[+]" in line:
            print(f"\033[32m{line}\033[0m") # Green
        elif "[!]" in line:
            print(f"\033[31m{line}\033[0m") # Red
        else:
            print(line)
    
    async def run(self, subdomains: List[str]) -> List[Dict[str, Any]]:
        """
        Check which subdomains are alive and gather info.
        
        Args:
            subdomains: List of subdomain names to check
            
        Returns:
            List of subdomain info dictionaries
        """
        self.work_dir.mkdir(parents=True, exist_ok=True)
        
        # Write subdomains to file for tools that need input file
        input_file = self.work_dir / "subdomains_input.txt"
        write_lines(input_file, subdomains)
        
        await self.log(f"[*] Checking {len(subdomains)} subdomains...")
        
        results = {}
        
        # Initialize results for all subdomains
        for sub in subdomains:
            results[sub.lower()] = {
                "subdomain": sub,
                "is_alive": False,
                "ip": None,
                "status_code": None,
                "title": None,
                "tech_stack": [],
                "cdn": None,
            }
        
        # Run tools in parallel
        tasks = []
        
        if await executor.check_tool("httpx"):
            tasks.append(self._run_httpx(input_file, results))
        else:
            await self.log("[!] httpx not found, skipping HTTP probing")
        
        if await executor.check_tool("dnsx"):
            tasks.append(self._run_dnsx(input_file, results))
        else:
            await self.log("[!] dnsx not found, skipping DNS resolution")
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        
        # Count alive
        alive_count = sum(1 for r in results.values() if r["is_alive"])
        await self.log(f"[+] Found {alive_count} alive subdomains out of {len(subdomains)}")
        
        # Save alive subdomains
        alive_file = self.work_dir / "alive_subdomains.txt"
        alive_list = [r["subdomain"] for r in results.values() if r["is_alive"]]
        write_lines(alive_file, alive_list)
        
        return list(results.values())
    
    async def _run_httpx(self, input_file: Path, results: Dict) -> None:
        """
        Run HTTPx to probe HTTP services.
        
        Extracts: status code, title, technologies, CDN detection
        """
        await self.log("[*] Running HTTPx...")
        
        output_file = self.work_dir / "httpx_output.json"
        
        # Run httpx with JSON output for easier parsing
        result = await executor.run(
            "httpx",
            [
                "-l", str(input_file),
                "-ports", settings.HTTPX_PORTS,
                "-threads", str(settings.HTTPX_THREADS),
                "-json",
                "-title",
                "-status-code",
                "-tech-detect",
                "-cdn",
                "-ip",
                "-o", str(output_file),
            ],
            timeout=600,
            on_output=self._print_progress,
            include_stderr=True,
        )
        
        if result.success or output_file.exists():
            await self._parse_httpx_json(output_file, results)
            await self.log(f"[+] HTTPx completed")
        else:
            await self.log(f"[!] HTTPx failed: {result.error_message}")
    
    async def _parse_httpx_json(self, output_file: Path, results: Dict) -> None:
        """Parse HTTPx JSON output and update results."""
        if not output_file.exists():
            return
        
        with open(output_file, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                try:
                    data = json.loads(line.strip())
                    
                    # Extract the hostname from the URL
                    url = data.get("url", "")
                    host = data.get("host", "")
                    
                    if not host:
                        # Try to extract from URL
                        match = re.search(r'https?://([^/:]+)', url)
                        if match:
                            host = match.group(1)
                    
                    host = host.lower()
                    
                    if host in results:
                        results[host]["is_alive"] = True
                        results[host]["status_code"] = data.get("status_code")
                        results[host]["title"] = data.get("title")
                        results[host]["ip"] = data.get("a", [None])[0] if data.get("a") else data.get("host")
                        
                        # Technology stack
                        tech = data.get("tech", [])
                        if tech:
                            results[host]["tech_stack"] = tech
                        
                        # CDN detection
                        cdn = data.get("cdn_name")
                        if cdn:
                            results[host]["cdn"] = cdn
                        
                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    logger.debug(f"Error parsing httpx line: {e}")
    
    async def _run_dnsx(self, input_file: Path, results: Dict) -> None:
        """Run DNSX for DNS resolution."""
        await self.log("[*] Running DNSX...")
        
        output_file = self.work_dir / "dnsx_output.txt"
        
        result = await executor.run(
            "dnsx",
            [
                "-l", str(input_file),
                "-a",        # Resolve A records
                "-resp",     # Include response
                "-o", str(output_file),
            ],
            timeout=300,
            on_output=self._print_progress,
            include_stderr=True,
        )
        
        if result.success or output_file.exists():
            # Parse DNSX output (format: subdomain [IP])
            with open(output_file, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        subdomain = parts[0].lower().rstrip('.')
                        ip = parts[1].strip('[]')
                        
                        if subdomain in results:
                            results[subdomain]["ip"] = ip
            
            await self.log("[+] DNSX completed")
        else:
            await self.log(f"[!] DNSX failed: {result.error_message}")
