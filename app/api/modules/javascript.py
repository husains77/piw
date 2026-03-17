"""
JavaScript Analysis Module

Analyzes JavaScript files for:
- Hidden API endpoints (LinkFinder)
- Secrets and API keys (SecretFinder)
- Vulnerable libraries (Retire.js)

JavaScript files often contain sensitive information and hidden endpoints.
"""

import asyncio
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Callable, Optional

from loguru import logger

from app.core.executor import executor
from app.utils.helpers import read_lines, write_lines


class JavaScriptAnalyzer:
    """
    JavaScript file analyzer for secrets and endpoints.
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
    
    async def run(self, js_urls: List[str]) -> Dict[str, Any]:
        """
        Analyze JavaScript files.
        
        Args:
            js_urls: List of JavaScript file URLs
            
        Returns:
            Dictionary with endpoints and secrets found
        """
        self.work_dir.mkdir(parents=True, exist_ok=True)
        
        if not js_urls:
            await self.log("[!] No JavaScript files to analyze")
            return {"endpoints": [], "secrets": []}
        
        await self.log(f"[*] Analyzing {len(js_urls)} JavaScript files...")
        
        # Write JS URLs to file
        input_file = self.work_dir / "js_files.txt"
        write_lines(input_file, js_urls)
        
        results = {
            "endpoints": [],
            "secrets": [],
        }
        
        # Run analysis tools
        tasks = []
        
        if await executor.check_tool("linkfinder") or await executor.check_tool("linkfinder.py"):
            tasks.append(self._run_linkfinder(js_urls))
        
        # Run basic regex analysis for secrets
        tasks.append(self._analyze_secrets(js_urls))
        
        if tasks:
            tool_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in tool_results:
                if isinstance(result, Exception):
                    await self.log(f"[!] Analysis error: {str(result)}")
                elif isinstance(result, dict):
                    results["endpoints"].extend(result.get("endpoints", []))
                    results["secrets"].extend(result.get("secrets", []))
        
        await self.log(f"[+] Found {len(results['endpoints'])} endpoints")
        await self.log(f"[+] Found {len(results['secrets'])} potential secrets")
        
        # Save results
        endpoints_file = self.work_dir / "js_endpoints.txt"
        write_lines(endpoints_file, [e["endpoint"] for e in results["endpoints"]])
        
        return results
    
    async def _run_linkfinder(self, js_urls: List[str]) -> Dict[str, List]:
        """Run LinkFinder to extract endpoints from JS."""
        await self.log("[*] Running LinkFinder...")
        
        endpoints = []
        
        for js_url in js_urls[:50]:  # Limit
            result = await executor.run(
                "python3",  # LinkFinder is a Python script
                [
                    "-m", "linkfinder",
                    "-i", js_url,
                    "-o", "cli",
                ],
                timeout=60,
            )
            
            if result.success:
                for line in result.stdout.splitlines():
                    endpoint = line.strip()
                    if endpoint and not endpoint.startswith("#"):
                        endpoints.append({
                            "endpoint": endpoint,
                            "source": js_url,
                        })
        
        await self.log(f"[+] LinkFinder found {len(endpoints)} endpoints")
        
        return {"endpoints": endpoints, "secrets": []}
    
    async def _analyze_secrets(self, js_urls: List[str]) -> Dict[str, List]:
        """Analyze JS files for secrets using regex patterns."""
        await self.log("[*] Scanning for secrets in JS files...")
        
        secrets = []
        
        # Common secret patterns
        patterns = {
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "AWS Secret Key": r"[A-Za-z0-9/+=]{40}",
            "GitHub Token": r"ghp_[a-zA-Z0-9]{36}",
            "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
            "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
            "Private Key": r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
            "JWT Token": r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
            "API Key Generic": r"['\"]?api[_-]?key['\"]?\s*[:=]\s*['\"][a-zA-Z0-9]{20,}['\"]",
            "Secret Generic": r"['\"]?secret['\"]?\s*[:=]\s*['\"][a-zA-Z0-9]{10,}['\"]",
            "Password": r"['\"]?password['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]",
            "Bearer Token": r"['\"]?bearer\s+[a-zA-Z0-9_\-\.=]+['\"]?",
            "Authorization Header": r"['\"]?authorization['\"]?\s*[:=]\s*['\"][^'\"]+['\"]",
        }
        
        import httpx
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            for js_url in js_urls[:30]:  # Limit
                try:
                    response = await client.get(js_url)
                    
                    if response.status_code == 200:
                        content = response.text
                        
                        for secret_type, pattern in patterns.items():
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            
                            for match in matches[:5]:  # Limit matches per pattern
                                secrets.append({
                                    "type": secret_type,
                                    "url": js_url,
                                    "secret": match if len(match) < 100 else match[:50] + "...",
                                })
                                
                except Exception as e:
                    continue
        
        await self.log(f"[+] Found {len(secrets)} potential secrets")
        
        return {"endpoints": [], "secrets": secrets}
