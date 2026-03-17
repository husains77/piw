"""
Helper Utilities

Common helper functions used across the application.
"""

import re
from pathlib import Path
from typing import List, Set, Optional
from urllib.parse import urlparse, parse_qs


def read_lines(file_path: Path) -> List[str]:
    """
    Read non-empty lines from a file.
    
    Args:
        file_path: Path to the file
        
    Returns:
        List of non-empty, stripped lines
    """
    if not file_path.exists():
        return []
    
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        return [line.strip() for line in f if line.strip()]


def write_lines(file_path: Path, lines: List[str]):
    """
    Write lines to a file.
    
    Args:
        file_path: Path to the output file
        lines: List of lines to write
    """
    file_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(file_path, 'w', encoding='utf-8') as f:
        for line in lines:
            f.write(f"{line}\n")


def deduplicate_file(file_path: Path) -> int:
    """
    Remove duplicate lines from a file.
    
    Args:
        file_path: Path to the file to deduplicate
        
    Returns:
        Number of unique lines after deduplication
    """
    if not file_path.exists():
        return 0
    
    lines = read_lines(file_path)
    unique_lines = list(dict.fromkeys(lines))  # Preserve order
    write_lines(file_path, unique_lines)
    
    return len(unique_lines)


def merge_files(input_files: List[Path], output_file: Path, dedupe: bool = True) -> int:
    """
    Merge multiple files into one.
    
    Args:
        input_files: List of input file paths
        output_file: Path to output file
        dedupe: Whether to remove duplicates
        
    Returns:
        Number of lines in output file
    """
    all_lines = []
    
    for file_path in input_files:
        all_lines.extend(read_lines(file_path))
    
    if dedupe:
        all_lines = list(dict.fromkeys(all_lines))
    
    write_lines(output_file, all_lines)
    
    return len(all_lines)


def is_valid_domain(domain: str) -> bool:
    """
    Validate a domain name.
    
    Args:
        domain: Domain to validate
        
    Returns:
        True if valid domain format
    """
    pattern = re.compile(
        r'^(?:[a-zA-Z0-9]'
        r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'
        r'+[a-zA-Z]{2,}$'
    )
    return bool(pattern.match(domain))


def extract_domain(url: str) -> Optional[str]:
    """
    Extract the domain from a URL.
    
    Args:
        url: Full URL
        
    Returns:
        Domain name or None if invalid
    """
    try:
        parsed = urlparse(url)
        return parsed.netloc or parsed.path.split('/')[0]
    except Exception:
        return None


def extract_params(url: str) -> List[str]:
    """
    Extract parameter names from a URL.
    
    Args:
        url: URL with query parameters
        
    Returns:
        List of parameter names
    """
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return list(params.keys())
    except Exception:
        return []


def classify_url(url: str) -> dict:
    """
    Classify a URL by type and characteristics.
    
    Args:
        url: URL to classify
        
    Returns:
        Dictionary with classification info
    """
    parsed = urlparse(url)
    path = parsed.path.lower()
    
    # Detect file type
    file_type = None
    if '.' in path:
        ext = path.rsplit('.', 1)[-1]
        if ext in ('js', 'json', 'xml', 'txt', 'log', 'yml', 'yaml', 'config'):
            file_type = ext
    
    # Check if API endpoint
    is_api = any(x in url.lower() for x in ['/api/', '/v1/', '/v2/', '/v3/', '/graphql'])
    
    # Check for parameters
    params = extract_params(url)
    
    return {
        "file_type": file_type,
        "is_api": is_api,
        "has_params": len(params) > 0,
        "param_names": params,
    }


def sanitize_filename(name: str) -> str:
    """
    Sanitize a string for use as a filename.
    
    Args:
        name: String to sanitize
        
    Returns:
        Safe filename string
    """
    # Replace unsafe characters
    safe = re.sub(r'[^\w\-.]', '_', name)
    # Limit length
    return safe[:200]
