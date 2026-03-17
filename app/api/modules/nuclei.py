"""
Nuclei Scanning Module

Comprehensive vulnerability scanning using Nuclei templates:
- CVEs (known vulnerabilities)
- Misconfigurations
- Exposures (config files, secrets)
- Takeovers

Nuclei is the primary scanning engine for automated vulnerability detection.
"""

import asyncio
import json
from pathlib import Path
from typing import List, Dict, Any, Callable, Optional

from loguru import logger

from app.core.executor import executor
from app.utils.helpers import read_lines, write_lines
from app.config import settings


class NucleiScanner:
    """
    Nuclei vulnerability scanner.
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
        Run Nuclei scan on targets.
        
        Args:
            targets: List of targets (subdomains or URLs)
            
        Returns:
            List of vulnerability dictionaries
        """
        self.work_dir.mkdir(parents=True, exist_ok=True)
        
        if not await executor.check_tool("nuclei"):
            await self.log("[!] Nuclei not found, skipping")
            return []
        
        await self.log(f"[*] Running Nuclei on {len(targets)} targets...")
        
        # Write targets to file
        input_file = self.work_dir / "nuclei_targets.txt"
        write_lines(input_file, targets)
        
        # Update templates first
        await self._update_templates()
        
        vulnerabilities = []
        
        # Run different template categories
        categories = [
            ("Critical & High CVEs", f"-s {settings.NUCLEI_SEVERITY}"),
            ("Exposures", "-t http/exposures/"),
            ("Misconfigurations", "-t http/misconfiguration/"),
            ("Takeovers", "-t http/takeovers/"),
        ]
        
        for category_name, template_args in categories:
            await self.log(f"[*] Scanning: {category_name}...")
            
            output_file = self.work_dir / f"nuclei_{category_name.lower().replace(' ', '_')}.json"
            
            # Build command args
            args = [
                "-l", str(input_file),
                "-rl", str(settings.NUCLEI_RATE_LIMIT),
                "-c", str(settings.NUCLEI_CONCURRENCY),
                "-bs", str(settings.NUCLEI_BULK_SIZE),
                "-jsonl",
                "-o", str(output_file),
            ]
            
            # Add template args
            args.extend(template_args.split())
            
            result = await executor.run(
                "nuclei",
                args,
                timeout=3600,  # 1 hour
            )
            
            # Parse results
            if output_file.exists():
                cat_vulns = self._parse_nuclei_output(output_file)
                vulnerabilities.extend(cat_vulns)
                await self.log(f"    Found {len(cat_vulns)} issues")
        
        # Deduplicate
        seen = set()
        unique_vulns = []
        for vuln in vulnerabilities:
            key = (vuln["url"], vuln.get("template_id", ""))
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)
        
        await self.log(f"[+] Nuclei found {len(unique_vulns)} total vulnerabilities")
        
        return unique_vulns
    
    async def _update_templates(self):
        """Update Nuclei templates."""
        await self.log("[*] Updating Nuclei templates...")
        
        result = await executor.run(
            "nuclei",
            ["-update-templates"],
            timeout=300,
        )
        
        if result.success:
            await self.log("[+] Templates updated")
        else:
            await self.log("[!] Template update failed (using cached)")
    
    def _parse_nuclei_output(self, output_file: Path) -> List[Dict[str, Any]]:
        """Parse Nuclei JSON output."""
        vulnerabilities = []
        
        try:
            for line in read_lines(output_file):
                try:
                    data = json.loads(line)
                    
                    # Extract info
                    info = data.get("info", {})
                    
                    vulnerabilities.append({
                        "type": info.get("name", "nuclei"),
                        "severity": info.get("severity", "info"),
                        "url": data.get("matched-at", data.get("host", "")),
                        "template_id": data.get("template-id", ""),
                        "evidence": data.get("matcher-name", ""),
                        "tool": "nuclei",
                        "description": info.get("description", ""),
                        "reference": info.get("reference", []),
                    })
                except json.JSONDecodeError:
                    continue
        except Exception as e:
            logger.error(f"Error parsing Nuclei output: {e}")
        
        return vulnerabilities
    
    async def run_custom_templates(
        self,
        targets: List[str],
        template_path: str
    ) -> List[Dict[str, Any]]:
        """
        Run Nuclei with custom templates.
        
        Args:
            targets: List of targets
            template_path: Path to custom templates
            
        Returns:
            List of vulnerabilities
        """
        await self.log(f"[*] Running custom templates: {template_path}")
        
        input_file = self.work_dir / "nuclei_custom_targets.txt"
        write_lines(input_file, targets)
        
        output_file = self.work_dir / "nuclei_custom.json"
        
        result = await executor.run(
            "nuclei",
            [
                "-l", str(input_file),
                "-t", template_path,
                "-jsonl",
                "-o", str(output_file),
            ],
            timeout=1800,
        )
        
        if output_file.exists():
            return self._parse_nuclei_output(output_file)
        
        return []
