"""
URL Collection Module

Collects URLs from multiple sources:
- Waybackurls: Archive.org historical URLs
- GAU: GetAllUrls from multiple sources
- Katana: Active JavaScript-aware crawler
- Hakrawler: Fast web crawler
- ParamSpider: Parameter discovery

URLs are classified by type (JS, API, etc.) and parameters extracted.
"""

import asyncio
from pathlib import Path
from typing import List, Dict, Any, Callable, Optional
from urllib.parse import urlparse, parse_qs

from loguru import logger

from app.core.executor import executor
from app.utils.helpers import read_lines, write_lines, classify_url


class URLCollector:
    """
    Collect URLs from historical archives and active crawling.
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
        Collect URLs for the given subdomains.
        
        Args:
            subdomains: List of alive subdomains
            
        Returns:
            List of URL dictionaries with classification info
        """
        self.work_dir.mkdir(parents=True, exist_ok=True)
        
        # Write subdomains for tools
        input_file = self.work_dir / "alive_subdomains.txt"
        write_lines(input_file, subdomains)
        
        await self.log(f"[*] Collecting URLs for {len(subdomains)} subdomains...")
        
        all_urls = []
        
        # Run collection tools
        tasks = []
        
        if await executor.check_tool("waybackurls"):
            tasks.append(self._run_waybackurls(subdomains))
        
        if await executor.check_tool("gau"):
            tasks.append(self._run_gau(subdomains))
        
        if await executor.check_tool("katana"):
            tasks.append(self._run_katana(input_file))
        
        if await executor.check_tool("hakrawler"):
            tasks.append(self._run_hakrawler(input_file))
        
        if await executor.check_tool("paramspider"):
            tasks.append(self._run_paramspider(input_file))
        
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, Exception):
                    await self.log(f"[!] Tool error: {str(result)}")
                elif isinstance(result, list):
                    all_urls.extend(result)
        else:
            await self.log("[!] No URL collection tools available")
        
        # Deduplicate
        seen = set()
        unique_urls = []
        for url_data in all_urls:
            url = url_data["url"]
            if url not in seen:
                seen.add(url)
                unique_urls.append(url_data)
        
        # Save all URLs
        output_file = self.work_dir / "all_urls.txt"
        write_lines(output_file, [u["url"] for u in unique_urls])
        
        # Save URLs with parameters
        param_urls = [u for u in unique_urls if u.get("has_params")]
        param_file = self.work_dir / "urls_with_params.txt"
        write_lines(param_file, [u["url"] for u in param_urls])
        
        # Save JS files
        js_urls = [u for u in unique_urls if u.get("file_type") == "js"]
        js_file = self.work_dir / "js_files.txt"
        write_lines(js_file, [u["url"] for u in js_urls])
        
        # Save API endpoints
        api_urls = [u for u in unique_urls if u.get("is_api")]
        api_file = self.work_dir / "api_endpoints.txt"
        write_lines(api_file, [u["url"] for u in api_urls])
        
        await self.log(f"[+] Collected {len(unique_urls)} unique URLs")
        await self.log(f"    - {len(param_urls)} with parameters")
        await self.log(f"    - {len(js_urls)} JavaScript files")
        await self.log(f"    - {len(api_urls)} API endpoints")
        
        return unique_urls
    
    def _classify_and_create_url_data(self, url: str, source: str) -> Dict[str, Any]:
        """Classify a URL and create data dictionary."""
        classification = classify_url(url)
        
        return {
            "url": url,
            "source": source,
            "has_params": classification["has_params"],
            "param_names": classification["param_names"],
            "file_type": classification["file_type"],
            "is_api": classification["is_api"],
        }
    
    async def _run_waybackurls(self, subdomains: List[str]) -> List[Dict[str, Any]]:
        """Run waybackurls for each subdomain."""
        await self.log("[*] Running waybackurls...")
        
        urls = []
        
        # Process in batches to avoid overwhelming
        for subdomain in subdomains[:50]:  # Limit to first 50
            result = await executor.run(
                "waybackurls",
                [subdomain],
                timeout=120,
                on_output=self._print_progress,
                include_stderr=True,
            )
            
            if result.success:
                for line in result.stdout.splitlines():
                    url = line.strip()
                    if url and url.startswith("http"):
                        urls.append(self._classify_and_create_url_data(url, "waybackurls"))
        
        await self.log(f"[+] Waybackurls found {len(urls)} URLs")
        
        # Save to file
        output_file = self.work_dir / "waybackurls.txt"
        write_lines(output_file, [u["url"] for u in urls])
        
        return urls
    
    async def _run_gau(self, subdomains: List[str]) -> List[Dict[str, Any]]:
        """Run GAU (GetAllUrls)."""
        await self.log("[*] Running GAU...")
        
        output_file = self.work_dir / "gau.txt"
        
        # GAU can take multiple domains via stdin
        input_data = "\n".join(subdomains[:50])
        
        result = await executor.run_with_input(
            "gau",
            ["--o", str(output_file)],
            input_data=input_data,
            timeout=600,
            on_output=self._print_progress,
            include_stderr=True,
        )
        
        urls = []
        if output_file.exists():
            for line in read_lines(output_file):
                if line.startswith("http"):
                    urls.append(self._classify_and_create_url_data(line, "gau"))
        
        await self.log(f"[+] GAU found {len(urls)} URLs")
        
        return urls
    
    async def _run_katana(self, input_file: Path) -> List[Dict[str, Any]]:
        """Run Katana crawler."""
        await self.log("[*] Running Katana...")
        
        output_file = self.work_dir / "katana.txt"
        
        result = await executor.run(
            "katana",
            [
                "-list", str(input_file),
                "-d", "3",                    # Crawl depth
                "-jc",                         # JavaScript crawling
                "-kf", "all",                  # Known files
                "-ef", "woff,css,png,svg,jpg,jpeg,gif",  # Exclude extensions
            "-o", str(output_file),
            ],
            timeout=900,
            on_output=self._print_progress,
            include_stderr=True,
        )
        
        urls = []
        if output_file.exists():
            for line in read_lines(output_file):
                if line.startswith("http"):
                    urls.append(self._classify_and_create_url_data(line, "katana"))
        
        await self.log(f"[+] Katana found {len(urls)} URLs")
        
        return urls
    
    async def _run_hakrawler(self, input_file: Path) -> List[Dict[str, Any]]:
        """Run Hakrawler."""
        await self.log("[*] Running Hakrawler...")
        
        # Hakrawler reads from stdin
        subdomains = read_lines(input_file)
        input_data = "\n".join([f"https://{s}" for s in subdomains[:20]])
        
        result = await executor.run_with_input(
            "hakrawler",
            ["-d", "3", "-u"],  # depth 3, unique
            input_data=input_data,
            timeout=600,
            on_output=self._print_progress,
            include_stderr=True,
        )
        
        urls = []
        if result.success:
            for line in result.stdout.splitlines():
                url = line.strip()
                if url.startswith("http"):
                    urls.append(self._classify_and_create_url_data(url, "hakrawler"))
        
        await self.log(f"[+] Hakrawler found {len(urls)} URLs")
        
        # Save
        output_file = self.work_dir / "hakrawler.txt"
        write_lines(output_file, [u["url"] for u in urls])
        
        return urls
    
    async def _run_paramspider(self, input_file: Path) -> List[Dict[str, Any]]:
        """Run ParamSpider for parameter discovery."""
        await self.log("[*] Running ParamSpider...")
        
        output_file = self.work_dir / "paramspider.txt"
        
        result = await executor.run(
            "paramspider",
            [
                "-l", str(input_file),
            "-o", str(output_file),
            ],
            timeout=600,
            on_output=self._print_progress,
            include_stderr=True,
        )
        
        urls = []
        if output_file.exists():
            for line in read_lines(output_file):
                if line.startswith("http"):
                    url_data = self._classify_and_create_url_data(line, "paramspider")
                    url_data["has_params"] = True  # ParamSpider specifically finds params
                    urls.append(url_data)
        
        await self.log(f"[+] ParamSpider found {len(urls)} URLs with parameters")
        
        return urls
