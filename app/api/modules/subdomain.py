"""
Subdomain Enumeration Module

Discovers subdomains using multiple tools and sources:
- Subfinder: Fast passive subdomain discovery
- Assetfinder: Find related domains
- Amass: In-depth DNS enumeration
- crt.sh: Certificate transparency logs

All results are merged and deduplicated.
"""

import asyncio
from pathlib import Path
from typing import List, Dict, Any, Callable, Optional
import json
import httpx

from loguru import logger

from app.core.executor import executor, ExecutionResult
from app.utils.helpers import read_lines, write_lines, merge_files


class SubdomainScanner:
    """
    Subdomain enumeration using multiple tools.
    
    Runs available tools in parallel and merges results.
    """
    
    def __init__(
        self,
        domain: str,
        work_dir: Path,
        log_callback: Optional[Callable] = None
    ):
        """
        Initialize the scanner.
        
        Args:
            domain: Target domain to enumerate
            work_dir: Directory to store output files
            log_callback: Async function to call with log messages
        """
        self.domain = domain
        self.work_dir = work_dir
        self.log = log_callback or self._default_log
    
    async def _default_log(self, msg: str):
        """Default logging function."""
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
    
    async def run(self) -> List[Dict[str, Any]]:
        """
        Run all available subdomain enumeration tools.
        
        Returns:
            List of subdomain dictionaries with 'subdomain' and 'source' keys
        """
        self.work_dir.mkdir(parents=True, exist_ok=True)
        
        all_subdomains = []
        
        # Define tools to run
        tools = [
            ("subfinder", self._run_subfinder),
            ("assetfinder", self._run_assetfinder),
            ("amass", self._run_amass),
            ("crt.sh", self._run_crtsh),
        ]
        
        # Check which tools are available and run them
        tasks = []
        for tool_name, tool_func in tools:
            if tool_name == "crt.sh":
                # crt.sh is an API, always available
                tasks.append(tool_func())
            elif await executor.check_tool(tool_name):
                tasks.append(tool_func())
            else:
                await self.log(f"[!] {tool_name} not found, skipping")
        
        # Run tools in parallel
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, Exception):
                    await self.log(f"[!] Tool error: {str(result)}")
                elif isinstance(result, list):
                    all_subdomains.extend(result)
        
        # Deduplicate while preserving source info
        seen = {}
        for sub in all_subdomains:
            subdomain = sub["subdomain"].lower().strip()
            if subdomain and subdomain not in seen:
                seen[subdomain] = sub
        
        unique_subdomains = list(seen.values())
        
        # Save merged results
        output_file = self.work_dir / "all_subdomains.txt"
        write_lines(output_file, [s["subdomain"] for s in unique_subdomains])
        
        await self.log(f"[+] Total unique subdomains: {len(unique_subdomains)}")
        
        return unique_subdomains
    
    async def _run_subfinder(self) -> List[Dict[str, Any]]:
        """Run subfinder."""
        await self.log("[*] Running subfinder...")
        
        output_file = self.work_dir / "subfinder.txt"
        
        result = await executor.run(
            "subfinder",
            ["-d", self.domain, "-all", "-recursive"],
            output_file=output_file,
            timeout=600,  # 10 minutes
            on_output=self._print_progress,
            include_stderr=True,
        )
        
        if result.success:
            await self.log(f"[+] Subfinder found {result.items_found} subdomains")
            subdomains = read_lines(output_file)
            return [{"subdomain": s, "source": "subfinder"} for s in subdomains]
        else:
            await self.log(f"[!] Subfinder failed: {result.error_message}")
            return []
    
    async def _run_assetfinder(self) -> List[Dict[str, Any]]:
        """Run assetfinder."""
        await self.log("[*] Running assetfinder...")
        
        output_file = self.work_dir / "assetfinder.txt"
        
        # assetfinder reads domain from args and outputs to stdout
        result = await executor.run(
            "assetfinder",
            ["--subs-only", self.domain],
            timeout=300,
            on_output=self._print_progress,
            include_stderr=True,
        )
        
        if result.success:
            # Parse stdout for subdomains
            subdomains = [
                line.strip() 
                for line in result.stdout.splitlines() 
                if line.strip() and self.domain in line
            ]
            
            # Save to file
            write_lines(output_file, subdomains)
            
            await self.log(f"[+] Assetfinder found {len(subdomains)} subdomains")
            return [{"subdomain": s, "source": "assetfinder"} for s in subdomains]
        else:
            await self.log(f"[!] Assetfinder failed: {result.error_message}")
            return []
    
    async def _run_amass(self) -> List[Dict[str, Any]]:
        """Run amass passive enumeration."""
        await self.log("[*] Running amass (passive mode)...")
        
        output_file = self.work_dir / "amass.txt"
        
        result = await executor.run(
            "amass",
            ["enum", "-passive", "-d", self.domain, "-o", str(output_file)],
            timeout=900,  # 15 minutes - amass can be slow
            on_output=self._print_progress,
            include_stderr=True,
        )
        
        if result.success or output_file.exists():
            subdomains = read_lines(output_file)
            await self.log(f"[+] Amass found {len(subdomains)} subdomains")
            return [{"subdomain": s, "source": "amass"} for s in subdomains]
        else:
            await self.log(f"[!] Amass failed: {result.error_message}")
            return []
    
    async def _run_crtsh(self) -> List[Dict[str, Any]]:
        """Query crt.sh certificate transparency logs."""
        await self.log("[*] Querying crt.sh...")
        
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.get(
                    f"https://crt.sh/?q={self.domain}&output=json"
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Extract unique subdomain names
                    subdomains = set()
                    for cert in data:
                        name = cert.get("name_value", "")
                        # Handle wildcard and multi-line entries
                        for line in name.split("\n"):
                            line = line.strip().lower()
                            if line.startswith("*."):
                                line = line[2:]
                            if self.domain in line:
                                subdomains.add(line)
                    
                    # Save to file
                    output_file = self.work_dir / "crtsh.txt"
                    write_lines(output_file, list(subdomains))
                    
                    await self.log(f"[+] crt.sh found {len(subdomains)} subdomains")
                    return [{"subdomain": s, "source": "crt.sh"} for s in subdomains]
                else:
                    await self.log(f"[!] crt.sh returned status {response.status_code}")
                    return []
                    
        except Exception as e:
            await self.log(f"[!] crt.sh query failed: {str(e)}")
            return []
