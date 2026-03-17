"""
Configuration Management for Recon Automation Platform

This module centralizes all configuration settings including:
- Database connection strings
- Tool paths and default arguments
- Scanning parameters and timeouts
- Directory paths for output storage
"""

import os
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    
    All settings can be overridden by setting environment variables
    with the same name (case-insensitive).
    
    Example:
        export DATABASE_URL="sqlite:///./custom.db"
        export HTTPX_THREADS=100
    """
    
    # ===================
    # Application Settings
    # ===================
    APP_NAME: str = "Recon Automation Platform"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True
    
    # Base directory (where the app is installed)
    BASE_DIR: Path = Path(__file__).parent.parent.resolve()
    
    # ===================
    # Database Settings
    # ===================
    DATABASE_URL: str = "sqlite+aiosqlite:///./data/recon.db"
    
    # ===================
    # Output Directories
    # ===================
    DATA_DIR: Path = Path("./data")
    RESULTS_DIR: Path = Path("./data/results")
    LOGS_DIR: Path = Path("./logs")
    
    # ===================
    # Tool Binary Paths
    # ===================
    # If tools are in PATH, just use the command name
    # Otherwise, specify full path like "/home/user/go/bin/subfinder"
    
    # Subdomain Enumeration
    SUBFINDER_PATH: str = "subfinder"
    ASSETFINDER_PATH: str = "assetfinder"
    AMASS_PATH: str = "amass"
    CHAOS_PATH: str = "chaos"
    GITHUB_SUBDOMAINS_PATH: str = "github-subdomains"
    
    # Alive Checking
    HTTPX_PATH: str = "/home/joko/go/bin/httpx"
    NAABU_PATH: str = "naabu"
    DNSX_PATH: str = "dnsx"
    
    # URL Collection
    WAYBACKURLS_PATH: str = "waybackurls"
    GAU_PATH: str = "gau"
    KATANA_PATH: str = "katana"
    HAKRAWLER_PATH: str = "hakrawler"
    GOSPIDER_PATH: str = "gospider"
    PARAMSPIDER_PATH: str = "paramspider"
    
    # Vulnerability Scanning
    DALFOX_PATH: str = "dalfox"
    KXSS_PATH: str = "kxss"
    SQLMAP_PATH: str = "sqlmap"
    GHAURI_PATH: str = "ghauri"
    NUCLEI_PATH: str = "nuclei"
    FFUF_PATH: str = "ffuf"
    DIRSEARCH_PATH: str = "dirsearch"
    
    # JavaScript Analysis
    GETJS_PATH: str = "getJS"
    LINKFINDER_PATH: str = "linkfinder"
    SECRETFINDER_PATH: str = "secretfinder"
    
    # API Testing
    ARJUN_PATH: str = "arjun"
    KITERUNNER_PATH: str = "kr"
    
    # Cloud Testing
    S3SCANNER_PATH: str = "s3scanner"
    CLOUD_ENUM_PATH: str = "cloud_enum"
    
    # ===================
    # Tool Default Settings
    # ===================
    
    # HTTPx settings
    HTTPX_THREADS: int = 100
    HTTPX_PORTS: str = "21,22,25,53,80,110,143,443,445,587,993,995,1433,3306,3389,5432,6379,8080,8443"
    HTTPX_TIMEOUT: int = 10
    
    # Naabu settings
    NAABU_CONCURRENCY: int = 50
    NAABU_TOP_PORTS: str = "1000"
    
    # Nuclei settings
    NUCLEI_SEVERITY: str = "critical,high,medium"
    NUCLEI_RATE_LIMIT: int = 150
    NUCLEI_BULK_SIZE: int = 25
    NUCLEI_CONCURRENCY: int = 25
    
    # FFuF settings
    FFUF_THREADS: int = 100
    FFUF_TIMEOUT: int = 10
    
    # General scanning settings
    DEFAULT_TIMEOUT: int = 3600  # 1 hour max per tool
    MAX_CONCURRENT_SCANS: int = 5
    
    # ===================
    # Wordlist Paths
    # ===================
    # Default wordlists - update these to match your system
    SECLISTS_DIR: str = "/home/joko/pentest/kambing-hunter/SecLists"
    DIRECTORY_WORDLIST: str = "/home/joko/pentest/kambing-hunter/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt"
    PARAMETER_WORDLIST: str = "/home/joko/pentest/kambing-hunter/SecLists/Discovery/Web-Content/burp-parameter-names.txt"
    LFI_WORDLIST: str = "/home/joko/pentest/kambing-hunter/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt"
    API_WORDLIST: str = "/home/joko/pentest/kambing-hunter/SecLists/Discovery/Web-Content/api/api-endpoints.txt"
    
    # ===================
    # API Keys (Optional)
    # ===================
    # These are optional - features requiring them will be skipped if not set
    GITHUB_TOKEN: Optional[str] = None
    SHODAN_API_KEY: Optional[str] = None
    SECURITYTRAILS_KEY: Optional[str] = None
    CHAOS_API_KEY: Optional[str] = None
    
    # ===================
    # WebSocket Settings
    # ===================
    WS_HEARTBEAT_INTERVAL: int = 30  # seconds
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
    
    def setup_directories(self):
        """Create necessary directories if they don't exist."""
        self.DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        self.LOGS_DIR.mkdir(parents=True, exist_ok=True)
    
    def get_project_dir(self, project_id: int) -> Path:
        """Get the output directory for a specific project."""
        project_dir = self.RESULTS_DIR / str(project_id)
        project_dir.mkdir(parents=True, exist_ok=True)
        return project_dir
    
    def get_scan_dir(self, project_id: int, scan_id: int) -> Path:
        """Get the output directory for a specific scan."""
        scan_dir = self.get_project_dir(project_id) / str(scan_id)
        scan_dir.mkdir(parents=True, exist_ok=True)
        return scan_dir


# Global settings instance
settings = Settings()

# Ensure directories exist on import
settings.setup_directories()
