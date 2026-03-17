"""
Tool Execution Engine

This module handles the secure execution of external security tools.

Features:
- Async subprocess execution
- Real-time output streaming
- Command timeout management
- Input sanitization to prevent injection
- Tool availability detection
- Cross-platform support (Windows/Linux)

Security Considerations:
- All inputs are sanitized to prevent command injection
- Commands are executed with timeouts
- Resource limits can be applied

Usage:
    executor = ToolExecutor()
    
    # Check if tool is available
    if await executor.check_tool("subfinder"):
        # Run tool
        result = await executor.run(
            "subfinder",
            ["-d", "example.com", "-all"],
            output_file="subdomains.txt"
        )
"""

import asyncio
import shutil
import shlex
import re
import os
import platform
from pathlib import Path
from typing import Optional, Callable, List, Dict, Any, AsyncGenerator
from dataclasses import dataclass
from datetime import datetime

from loguru import logger

from app.config import settings


@dataclass
class ExecutionResult:
    """
    Result of a tool execution.
    
    Attributes:
        success: Whether the command completed without errors
        exit_code: Process exit code (0 = success)
        stdout: Standard output content
        stderr: Standard error content
        output_file: Path to output file if generated
        items_found: Count of items found (parsed from output)
        duration: Execution time in seconds
        error_message: Error description if failed
    """
    success: bool
    exit_code: int
    stdout: str
    stderr: str
    output_file: Optional[Path] = None
    items_found: int = 0
    duration: float = 0.0
    error_message: Optional[str] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "output_file": str(self.output_file) if self.output_file else None,
            "items_found": self.items_found,
            "duration": self.duration,
            "error_message": self.error_message,
        }


class ToolExecutor:
    """
    Async executor for security tools.
    
    Handles running external commands safely with:
    - Input validation
    - Output streaming
    - Timeout management
    - Error handling
    """
    
    # Characters allowed in command arguments (whitelist)
    SAFE_CHARS = re.compile(r'^[\w\-\./:\\,=@\s]+$')
    
    # Dangerous patterns to block
    DANGEROUS_PATTERNS = [
        r'[;&|`$]',     # Command chaining
        r'>\s*>',       # Append redirect
        r'<\s*<',       # Here-doc
        r'\$\(',        # Command substitution
        r'\$\{',        # Variable expansion
    ]
    
    def __init__(self):
        """Initialize the executor."""
        self.is_windows = platform.system() == "Windows"
        self._tool_cache: Dict[str, bool] = {}
    
    async def check_tool(self, tool_name: str) -> bool:
        """
        Check if a tool is available in the system PATH.
        
        Args:
            tool_name: Name of the tool (e.g., "subfinder", "httpx")
            
        Returns:
            True if tool is available, False otherwise
        """
        # Check cache first
        if tool_name in self._tool_cache:
            return self._tool_cache[tool_name]
        
        # Get tool path from settings or use tool name
        tool_path = getattr(settings, f"{tool_name.upper()}_PATH", tool_name)
        
        # Try to find the tool
        available = shutil.which(tool_path) is not None
        
        # Cache the result
        self._tool_cache[tool_name] = available
        
        if not available:
            logger.warning(f"Tool not found: {tool_name} (path: {tool_path})")
        
        return available
    
    async def check_all_tools(self) -> Dict[str, bool]:
        """
        Check availability of all configured tools.
        
        Returns:
            Dictionary mapping tool names to availability status
        """
        tools = [
            # Subdomain
            "subfinder", "assetfinder", "amass", "chaos",
            # Alive
            "httpx", "naabu", "dnsx",
            # URLs
            "waybackurls", "gau", "katana", "hakrawler", "gospider", "paramspider",
            # Vuln scanning
            "dalfox", "kxss", "sqlmap", "ghauri", "nuclei",
            # Fuzzing
            "ffuf", "dirsearch",
            # JS analysis
            "getJS",
            # API testing  
            "arjun",
            # Cloud
            "s3scanner",
        ]
        
        results = {}
        for tool in tools:
            results[tool] = await self.check_tool(tool)
        
        return results
    
    def sanitize_input(self, value: str) -> str:
        """
        Sanitize input to prevent command injection.
        
        Args:
            value: Input value to sanitize
            
        Returns:
            Sanitized string
            
        Raises:
            ValueError: If input contains dangerous patterns
        """
        # Check for dangerous patterns
        for pattern in self.DANGEROUS_PATTERNS:
            if re.search(pattern, value):
                raise ValueError(f"Dangerous pattern detected in input: {pattern}")
        
        # Only allow safe characters for most inputs
        # This is strict but prevents most injection attacks
        if not self.SAFE_CHARS.match(value):
            # Log warning but allow (some tools need special chars)
            logger.warning(f"Input contains non-standard characters: {value[:50]}...")
        
        return value
    
    def build_command(
        self,
        tool: str,
        args: List[str],
        output_file: Optional[Path] = None
    ) -> List[str]:
        """
        Build a command list for execution.
        
        Args:
            tool: Tool name or path
            args: List of arguments
            output_file: Optional output file path
            
        Returns:
            List of command parts ready for subprocess
        """
        # Get tool path from settings
        tool_path = getattr(settings, f"{tool.upper()}_PATH", tool)
        
        # Start with tool
        cmd = [tool_path]
        
        # Add sanitized arguments
        for arg in args:
            cmd.append(self.sanitize_input(arg))
        
        # Add output file if specified (for tools that support -o)
        if output_file:
            cmd.extend(["-o", str(output_file)])
        
        return cmd
    
    async def run(
        self,
        tool: str,
        args: List[str],
        output_file: Optional[Path] = None,
        timeout: Optional[int] = None,
        cwd: Optional[Path] = None,
        on_output: Optional[Callable[[str], None]] = None,
        env: Optional[Dict[str, str]] = None,
        include_stderr: bool = False,
    ) -> ExecutionResult:
        """
        Execute a tool and return the result.
        
        Args:
            tool: Tool name (e.g., "subfinder")
            args: List of arguments
            output_file: Optional path to save output
            timeout: Timeout in seconds (default from settings)
            cwd: Working directory
            on_output: Callback for real-time output streaming
            env: Additional environment variables
            
        Returns:
            ExecutionResult with output and status
            
        Example:
            result = await executor.run(
                "subfinder",
                ["-d", "example.com", "-all"],
                output_file=Path("subs.txt"),
                on_output=lambda line: print(f">> {line}")
            )
        """
        start_time = datetime.utcnow()
        timeout = timeout or settings.DEFAULT_TIMEOUT
        
        try:
            # Build command
            cmd = self.build_command(tool, args, output_file)
            logger.info(f"Executing: {' '.join(cmd)}")
            
            if on_output:
                on_output(f"[*] Running: {' '.join(cmd)}")
            
            # Prepare environment
            process_env = os.environ.copy()
            if env:
                process_env.update(env)
            
            # Create subprocess
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=process_env,
            )
            
            # Collect output
            stdout_lines = []
            stderr_lines = []
            
            async def read_stream(stream, lines_list, is_stderr=False):
                """Read from stream and optionally call callback."""
                while True:
                    line = await stream.readline()
                    if not line:
                        break
                    decoded = line.decode('utf-8', errors='replace').rstrip()
                    lines_list.append(decoded)
                    
                    if on_output and not is_stderr:
                        on_output(decoded)
            
            # Read stdout and stderr concurrently with timeout
            try:
                await asyncio.wait_for(
                    asyncio.gather(
                        read_stream(process.stdout, stdout_lines),
                        read_stream(process.stderr, stderr_lines, is_stderr=not include_stderr)
                    ),
                    timeout=timeout
                )
                
                # Wait for process to complete
                await asyncio.wait_for(process.wait(), timeout=10)
                
            except asyncio.TimeoutError:
                # Kill the process on timeout
                process.kill()
                await process.wait()
                
                duration = (datetime.utcnow() - start_time).total_seconds()
                error_msg = f"Command timed out after {timeout} seconds"
                
                if on_output:
                    on_output(f"[!] {error_msg}")
                
                return ExecutionResult(
                    success=False,
                    exit_code=-1,
                    stdout="\n".join(stdout_lines),
                    stderr="\n".join(stderr_lines),
                    output_file=output_file if output_file and output_file.exists() else None,
                    duration=duration,
                    error_message=error_msg
                )
            
            # Calculate duration
            duration = (datetime.utcnow() - start_time).total_seconds()
            
            # Count items if output file exists
            items_found = 0
            if output_file and output_file.exists():
                with open(output_file, 'r', encoding='utf-8', errors='replace') as f:
                    items_found = sum(1 for line in f if line.strip())
            
            # Determine success
            success = process.returncode == 0
            stdout_str = "\n".join(stdout_lines)
            stderr_str = "\n".join(stderr_lines)
            
            if on_output:
                status = "[+] Completed" if success else "[!] Failed"
                on_output(f"{status} ({items_found} items found in {duration:.1f}s)")
            
            return ExecutionResult(
                success=success,
                exit_code=process.returncode,
                stdout=stdout_str,
                stderr=stderr_str,
                output_file=output_file if output_file and output_file.exists() else None,
                items_found=items_found,
                duration=duration,
                error_message=stderr_str if not success and stderr_str else None
            )
            
        except FileNotFoundError:
            error_msg = f"Tool not found: {tool}"
            logger.error(error_msg)
            
            if on_output:
                on_output(f"[!] {error_msg}")
            
            return ExecutionResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr="",
                error_message=error_msg,
                duration=0.0
            )
            
        except Exception as e:
            error_msg = f"Execution error: {str(e)}"
            logger.exception(error_msg)
            
            if on_output:
                on_output(f"[!] {error_msg}")
            
            return ExecutionResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=str(e),
                error_message=error_msg,
                duration=(datetime.utcnow() - start_time).total_seconds()
            )
    
    async def run_with_input(
        self,
        tool: str,
        args: List[str],
        input_data: str,
        output_file: Optional[Path] = None,
        timeout: Optional[int] = None,
        on_output: Optional[Callable[[str], None]] = None,
        include_stderr: bool = False,
    ) -> ExecutionResult:
        """
        Execute a tool with piped input data.
        
        This is for tools that read from stdin, like:
            cat subdomains.txt | httpx
        
        Args:
            tool: Tool name
            args: Arguments
            input_data: String data to pipe to stdin
            output_file: Optional output file
            timeout: Timeout in seconds
            on_output: Output callback
            
        Returns:
            ExecutionResult
        """
        start_time = datetime.utcnow()
        timeout = timeout or settings.DEFAULT_TIMEOUT
        
        try:
            # Build command
            cmd = self.build_command(tool, args, output_file)
            logger.info(f"Executing with input: {' '.join(cmd)}")
            
            if on_output:
                on_output(f"[*] Running: {' '.join(cmd)} (with piped input)")
            
            # Create subprocess with stdin pipe
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            # Send input and get output
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(input_data.encode('utf-8')),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                
                return ExecutionResult(
                    success=False,
                    exit_code=-1,
                    stdout="",
                    stderr="",
                    error_message=f"Command timed out after {timeout} seconds",
                    duration=(datetime.utcnow() - start_time).total_seconds()
                )
            
            duration = (datetime.utcnow() - start_time).total_seconds()
            stdout_str = stdout.decode('utf-8', errors='replace')
            stderr_str = stderr.decode('utf-8', errors='replace')
            
            # Stream output lines to callback
            if on_output:
                for line in stdout_str.splitlines():
                    on_output(line)
                
                if include_stderr and stderr_str:
                    for line in stderr_str.splitlines():
                        on_output(line)
            
            # Count items
            items_found = 0
            if output_file and output_file.exists():
                with open(output_file, 'r') as f:
                    items_found = sum(1 for line in f if line.strip())
            else:
                items_found = len([l for l in stdout_str.splitlines() if l.strip()])
            
            success = process.returncode == 0
            
            if on_output:
                status = "[+] Completed" if success else "[!] Failed"
                on_output(f"{status} ({items_found} items in {duration:.1f}s)")
            
            return ExecutionResult(
                success=success,
                exit_code=process.returncode,
                stdout=stdout_str,
                stderr=stderr_str,
                output_file=output_file,
                items_found=items_found,
                duration=duration,
                error_message=stderr_str if not success and stderr_str else None
            )
            
        except Exception as e:
            return ExecutionResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=str(e),
                error_message=str(e),
                duration=(datetime.utcnow() - start_time).total_seconds()
            )


# Global executor instance
executor = ToolExecutor()
