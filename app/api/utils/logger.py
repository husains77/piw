"""
Logging Configuration

Sets up structured logging with:
- Colored console output for development
- Rotating file logs for production
- Error tracking and debugging support
"""

import sys
from pathlib import Path
from loguru import logger

from app.config import settings


def setup_logging():
    """
    Configure the application logger.
    
    Creates:
    - Console handler with colors
    - File handler with rotation
    - Error-specific file handler
    """
    # Remove default handler
    logger.remove()
    
    # Console handler - colored output
    logger.add(
        sys.stderr,
        format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>",
        level="DEBUG" if settings.DEBUG else "INFO",
        colorize=True,
    )
    
    # Ensure log directory exists
    log_dir = settings.LOGS_DIR
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Main log file with rotation
    logger.add(
        log_dir / "recon_{time:YYYY-MM-DD}.log",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
        level="DEBUG",
        rotation="00:00",     # New file every midnight
        retention="30 days",  # Keep for 30 days
        compression="zip",    # Compress old logs
        encoding="utf-8",
    )
    
    # Error-only log file
    logger.add(
        log_dir / "errors_{time:YYYY-MM-DD}.log",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}\n{exception}",
        level="ERROR",
        rotation="00:00",
        retention="90 days",
        compression="zip",
        encoding="utf-8",
        backtrace=True,
        diagnose=True,
    )
    
    logger.info("Logging initialized")
    return logger


# Initialize logging on module import
setup_logging()
