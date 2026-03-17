"""
API Testing Module

API endpoint discovery and testing:
- Arjun: Hidden parameter discovery
- Kiterunner: API route bruteforcing
"""

import asyncio
import json
from pathlib import Path
from typing import List, Dict, Any, Callable, Optional
from urllib.parse import urlparse

from loguru import logger
from app.core.executor import executor
from app.utils.helpers import read_lines, write_lines


class APITester:
    """API endpoint tester."""
    
    def __init__(self, work_dir: Path, log_callback: Optional[Callable] = None):
        self.work_dir = work_dir
        self.log = log_callback or (lambda msg: logger.info(msg))
    
    async def run(self, api_urls: List[str]) -> List[Dict[str, Any]]:
        """Test API endpoints and discover hidden parameters."""
        self.work_dir.mkdir(parents=True, exist_ok=True)
        
        if not api_urls:
            await self.log("[!] No API endpoints to test")
            return []
        
        await self.log(f"[*] Testing {len(api_urls)} API endpoints...")
        
        results = []
        
        if await executor.check_tool("arjun"):
            for url in api_urls[:10]:
                output_file = self.work_dir / f"arjun_{hash(url) % 10000}.json"
                result = await executor.run("arjun", ["-u", url, "-oJ", str(output_file)], timeout=300)
                
                if output_file.exists():
                    try:
                        with open(output_file, 'r') as f:
                            data = json.load(f)
                            for endpoint, params in data.items():
                                results.append({"type": "hidden_params", "url": endpoint, "parameters": params, "tool": "arjun"})
                    except Exception:
                        pass
        
        await self.log(f"[+] Discovered {len(results)} API findings")
        return results
