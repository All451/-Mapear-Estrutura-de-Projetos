"""
Cybersecurity Module - General Security Functions
This module contains general cybersecurity utilities and functions.
"""

import os
import sys
import hashlib
import subprocess
import stat
from datetime import datetime
from pathlib import Path


def security_audit():
    """Perform a basic security audit of the system"""
    print("Performing basic security audit...")
    
    # Check for common security issues
    issues = []
    
    # Check if system is running as root (security risk)
    if os.geteuid() == 0:
        issues.append("Running as root user - potential security risk")
    
    # Check for world-writable system directories
    system_dirs = ["/tmp", "/var/tmp", "/dev/shm"]
    for directory in system_dirs:
        if os.path.exists(directory):
            try:
                dir_stat = os.stat(directory)
                if dir_stat.st_mode & stat.S_IWOTH:
                    issues.append(f"World-writable directory found: {directory}")
            except (OSError, AttributeError):
                pass  # Skip if we can't check permissions
    
    # Report findings
    if issues:
        print(f"  Found {len(issues)} potential security issues:")
        for issue in issues:
            print(f"    - {issue}")
    else:
        print("  No immediate security issues detected")


def check_system_integrity():
    """Check system integrity for potential security issues"""
    print("Checking system integrity...")
    
    # Check for common backdoors and suspicious files
    suspicious_paths = [
        "/tmp/.X11-unix",  # Common location for malware
        "/dev/shm/.X11-unix",  # Another common location
        "/tmp/.ICE-unix",  # Another common location
    ]
    
    suspicious_files = []
    for path in suspicious_paths:
        if os.path.exists(path):
            suspicious_files.append(path)
    
    if suspicious_files:
        print(f"  Found {len(suspicious_files)} suspicious files/directories:")
        for file in suspicious_files:
            print(f"    - {file}")
    else:
        print("  No suspicious system files detected")


def get_file_hash(filepath):
    """
    Calculate SHA256 hash of a file safely
    
    Args:
        filepath (str): Path to the file
        
    Returns:
        str: SHA256 hash of the file or None if error
    """
    # Sanitize path to prevent directory traversal
    safe_path = Path(filepath).resolve()
    
    # Ensure the resolved path is within allowed directories
    # In a real implementation, you'd have a list of allowed base directories
    try:
        # Check if the resolved path is within the current working directory
        safe_path.relative_to(Path.cwd())
    except ValueError:
        raise ValueError(f"Path traversal detected: {filepath}")
    
    try:
        hash_sha256 = hashlib.sha256()
        with open(safe_path, "rb") as f:
            # Read file in chunks to handle large files efficiently
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except (OSError, IOError) as e:
        print(f"Error reading file {filepath}: {e}")
        return None


def scan_for_sensitive_files(directory=".", max_depth=3):
    """
    Safely scan for sensitive files in a directory with depth control
    
    Args:
        directory (str): Directory to scan
        max_depth (int): Maximum directory depth to scan
        
    Returns:
        list: List of sensitive files found
    """
    # Sanitize directory path to prevent directory traversal
    base_path = Path(directory).resolve()
    
    # Ensure the resolved path is within allowed directories
    try:
        base_path.relative_to(Path.cwd())
    except ValueError:
        raise ValueError(f"Path traversal detected: {directory}")
    
    sensitive_patterns = [
        '.env', 'config', 'password', 'secret', 'key', 'token', 
        '.pem', '.key', 'id_rsa', 'id_dsa', '.ssh', 'credentials',
        'passwd', 'shadow', 'htpasswd', '.git-credentials'
    ]
    
    sensitive_files = []
    
    # Walk through directory tree with depth control
    for root, dirs, files in os.walk(base_path):
        # Calculate current depth
        current_depth = len(Path(root).relative_to(base_path).parts)
        if current_depth > max_depth:
            # Remove subdirectories to prevent deeper traversal
            dirs.clear()
            continue
            
        # Skip hidden directories to avoid system files
        dirs[:] = [d for d in dirs if not d.startswith('.')]
        
        for file in files:
            # Check if the file matches any sensitive pattern
            file_lower = file.lower()
            if any(pattern in file_lower for pattern in sensitive_patterns):
                full_path = Path(root) / file
                # Verify the path is still within allowed base
                try:
                    full_path.relative_to(Path.cwd())
                    sensitive_files.append(str(full_path))
                except ValueError:
                    # Skip if path traversal detected
                    continue
    
    return sensitive_files


def check_file_permissions(filepath):
    """
    Check file permissions for security issues
    
    Args:
        filepath (str): Path to the file to check
        
    Returns:
        dict: Dictionary with permission information
    """
    try:
        file_stat = os.stat(filepath)
        permissions = {
            'readable_by_others': bool(file_stat.st_mode & stat.S_IROTH),
            'writable_by_others': bool(file_stat.st_mode & stat.S_IWOTH),
            'executable_by_others': bool(file_stat.st_mode & stat.S_IXOTH),
            'is_world_writable': bool(file_stat.st_mode & stat.S_IWOTH),
            'is_executable': bool(file_stat.st_mode & stat.S_IXUSR),
            'owner_readable': bool(file_stat.st_mode & stat.S_IRUSR),
            'owner_writable': bool(file_stat.st_mode & stat.S_IWUSR),
            'owner_executable': bool(file_stat.st_mode & stat.S_IXUSR),
            'group_readable': bool(file_stat.st_mode & stat.S_IRGRP),
            'group_writable': bool(file_stat.st_mode & stat.S_IWGRP),
            'group_executable': bool(file_stat.st_mode & stat.S_IXGRP)
        }
        return permissions
    except (OSError, IOError) as e:
        print(f"Error checking permissions for {filepath}: {e}")
        return {}


def log_security_event(event_type, description):
    """Log a security-related event"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {event_type}: {description}\n"
    
    # Try to write to system log, fallback to local file if no permissions
    try:
        with open("/var/log/security.log", "a") as log_file:
            log_file.write(log_entry)
    except (PermissionError, OSError):
        # Fallback to local log file
        try:
            with open("security.log", "a") as log_file:
                log_file.write(log_entry)
        except OSError:
            # If all else fails, just print to console
            print(f"Could not write to log file: {log_entry.strip()}")


def run_security_command(command, allowed_commands=None):
    """
    Safely run a security-related system command
    
    Args:
        command (str or list): Command to execute
        allowed_commands (list): List of allowed commands for validation
        
    Returns:
        subprocess.CompletedProcess: Result of the command execution
    """
    if allowed_commands is None:
        allowed_commands = ['ps', 'netstat', 'ss', 'lsof', 'find', 'grep', 'awk', 'sed', 'head', 'tail', 'cat', 'ls']
    
    # If command is a string, split it to check the base command
    if isinstance(command, str):
        base_cmd = command.split()[0]
    else:
        base_cmd = command[0]
    
    # Validate that the command is in the allowed list
    if base_cmd not in allowed_commands:
        raise ValueError(f"Command not allowed: {base_cmd}")
    
    try:
        # Use subprocess.run with security best practices
        result = subprocess.run(
            command,
            shell=isinstance(command, str),
            capture_output=True,
            text=True,
            timeout=30  # Prevent hanging commands
        )
        return result
    except subprocess.TimeoutExpired:
        print(f"Command timed out: {command}")
        raise
    except Exception as e:
        print(f"Error executing command: {e}")
        raise


if __name__ == "__main__":
    print("Cybersecurity Module loaded")