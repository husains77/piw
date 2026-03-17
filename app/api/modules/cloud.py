"""Cloud storage testing module."""

import asyncio
from pathlib import Path
from typing import List, Dict, Any, Callable, Optional
from loguru import logger
from app.core.executor import executor
from app.utils.helpers import write_lines


class CloudScanner:
    """Cloud storage misconfiguration scanner."""
    
    def __init__(self, work_dir: Path, log_callback: Optional[Callable] = None):
        self.work_dir = work_dir
        self.log = log_callback or (lambda msg: logger.info(msg))
    
    async def run(self, domain: str) -> List[Dict[str, Any]]:
        """Scan for misconfigured cloud storage buckets."""
        self.work_dir.mkdir(parents=True, exist_ok=True)
        
        await self.log(f"[*] Scanning cloud storage for {domain}...")
        
        results = []
        
        if await executor.check_tool("s3scanner"):
            output_file = self.work_dir / "s3scanner.txt"
            result = await executor.run("s3scanner", ["scan", "--bucket", domain], timeout=300)
            
            if result.success and "open" in result.stdout.lower():
                results.append({"type": "s3_bucket", "bucket": domain, "severity": "high", "details": result.stdout, "tool": "s3scanner"})
        
        await self.log(f"[+] Found {len(results)} cloud misconfigurations")
        return results
