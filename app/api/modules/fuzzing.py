"""
Fuzzing Module

Directory and parameter fuzzing:
- FFuF: Fast web fuzzer
- Dirsearch: Directory discovery

Discovers hidden files, directories, and endpoints.
"""

import asyncio
import json
from pathlib import Path
from typing import List, Dict, Any, Callable, Optional

from loguru import logger

from app.core.executor import executor
from app.utils.helpers import read_lines, write_lines
from app.config import settings


class FuzzingScanner:
    """
    Directory and content fuzzing scanner.
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
    
    async def run(self, targets: List[str]) -> List[Dict[str, Any]]:
        """
        Fuzz targets for hidden content.
        
        Args:
            targets: List of target URLs (base URLs)
            
        Returns:
            List of discovered endpoints
        """
        self.work_dir.mkdir(parents=True, exist_ok=True)
        
        await self.log(f"[*] Fuzzing {len(targets)} targets...")
        
        discovered = []
        
        # Run tools
        tasks = []
        
        if await executor.check_tool("ffuf"):
            tasks.append(self._run_ffuf(targets))
        else:
            await self.log("[!] FFuF not found")
        
        if await executor.check_tool("dirsearch"):
            tasks.append(self._run_dirsearch(targets[:5]))
        
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, Exception):
                    await self.log(f"[!] Tool error: {str(result)}")
                elif isinstance(result, list):
                    discovered.extend(result)
        
        # Deduplicate
        seen = set()
        unique = []
        for item in discovered:
            url = item["url"]
            if url not in seen:
                seen.add(url)
                unique.append(item)
        
        await self.log(f"[+] Discovered {len(unique)} endpoints")
        
        return unique
    
    async def _run_ffuf(self, targets: List[str]) -> List[Dict[str, Any]]:
        """Run FFuF directory fuzzing."""
        await self.log("[*] Running FFuF...")
        
        discovered = []
        
        # Use a smaller wordlist for faster scanning
        wordlist = settings.DIRECTORY_WORDLIST
        
        # Check if wordlist exists, otherwise use a basic one
        if not Path(wordlist).exists():
            # Create a basic wordlist
            basic_words = [
                "admin", "api", "backup", "config", "dashboard", "db",
                "debug", "dev", "docs", "download", "files", "images",
                "img", "include", "js", "lib", "log", "login", "logs",
                "manage", "old", "private", "public", "scripts", "server",
                "static", "test", "tmp", "upload", "uploads", "user",
                "users", "v1", "v2", "wp-admin", "wp-content", ".git",
                ".env", "robots.txt", "sitemap.xml", ".htaccess",
            ]
            wordlist = self.work_dir / "fuzzing_wordlist.txt"
            write_lines(wordlist, basic_words)
        
        for target in targets[:5]:  # Limit targets
            output_file = self.work_dir / f"ffuf_{hash(target) % 10000}.json"
            
            fuzz_url = target.rstrip('/') + "/FUZZ"
            
            result = await executor.run(
                "ffuf",
                [
                    "-w", str(wordlist),
                    "-u", fuzz_url,
                    "-mc", "200,301,302,403",  # Match these status codes
                    "-t", str(settings.FFUF_THREADS),
                    "-json",
                    "-o", str(output_file),
                ],
                timeout=600,
            )
            
            if output_file.exists():
                try:
                    with open(output_file, 'r') as f:
                        data = json.load(f)
                        
                        for res in data.get("results", []):
                            discovered.append({
                                "url": res.get("url", ""),
                                "status_code": res.get("status", 0),
                                "size": res.get("length", 0),
                                "source": "ffuf",
                            })
                except Exception as e:
                    await self.log(f"[!] Error parsing FFuF output: {e}")
        
        await self.log(f"[+] FFuF found {len(discovered)} endpoints")
        
        return discovered
    
    async def _run_dirsearch(self, targets: List[str]) -> List[Dict[str, Any]]:
        """Run dirsearch."""
        await self.log("[*] Running dirsearch...")
        
        discovered = []
        
        for target in targets:
            output_file = self.work_dir / f"dirsearch_{hash(target) % 10000}.json"
            
            result = await executor.run(
                "dirsearch",
                [
                    "-u", target,
                    "-t", "50",
                    "-e", "php,asp,aspx,jsp,html,js",
                    "-x", "400,403,404,500",
                    "--format", "json",
                    "-o", str(output_file),
                ],
                timeout=600,
            )
            
            if output_file.exists():
                try:
                    with open(output_file, 'r') as f:
                        data = json.load(f)
                        
                        for res in data.get("results", []):
                            discovered.append({
                                "url": res.get("url", ""),
                                "status_code": res.get("status", 0),
                                "size": res.get("content-length", 0),
                                "source": "dirsearch",
                            })
                except Exception:
                    pass
        
        await self.log(f"[+] Dirsearch found {len(discovered)} endpoints")
        
        return discovered
