"""Filesystem security scanner for the Cybersecurity Toolkit."""
import os
import stat
import pwd
import grp
import subprocess
from typing import List, Dict, Any
import logging
from pathlib import Path
import re

from cybersec.utils.config import get_config
from cybersec.utils.exceptions import ScanError

logger = logging.getLogger(__name__)


class FilesystemScanner:
    """Scans filesystem for security issues."""
    
    def __init__(self):
        """Initialize filesystem scanner."""
        self.config = get_config()
        self.max_file_size = self.config.get("scan.max_file_size", 10485760)  # 10MB
        self.check_hidden_files = self.config.get("scan.check_hidden_files", True)
        self.deep_scan = self.config.get("scan.deep_scan", False)
    
    def scan(self, path: str = "/") -> List[Dict[str, Any]]:
        """Perform comprehensive filesystem security scan.
        
        Args:
            path: Path to scan (default: root directory)
            
        Returns:
            List of security findings
        """
        findings = []
        
        try:
            scan_path = Path(path)
            if not scan_path.exists():
                raise ScanError(f"Path does not exist: {path}")
            
            # Walk through the directory tree
            for root, dirs, files in os.walk(scan_path, topdown=True, onerror=None):
                # Skip certain directories to avoid performance issues
                dirs[:] = [d for d in dirs if d not in ['.git', '__pycache__', 'node_modules', 'vendor']]
                
                # Check directory permissions
                findings.extend(self._check_directory_security(Path(root)))
                
                # Check files in directory
                for file in files:
                    file_path = Path(root) / file
                    try:
                        findings.extend(self._check_file_security(file_path))
                    except (OSError, PermissionError):
                        # Skip files we can't access
                        continue
                
                # Limit scan depth if not deep scanning
                if not self.deep_scan and len(root.split(os.sep)) - len(str(scan_path).split(os.sep)) >= 3:
                    del dirs[:]  # Don't continue deeper
        
        except Exception as e:
            logger.error(f"Error during filesystem scan: {e}")
            raise ScanError(f"Filesystem scan failed: {e}")
        
        logger.info(f"Filesystem scan completed with {len(findings)} findings")
        return findings
    
    def _check_directory_security(self, dir_path: Path) -> List[Dict[str, Any]]:
        """Check directory security settings.
        
        Args:
            dir_path: Directory path to check
            
        Returns:
            List of security findings for the directory
        """
        findings = []
        
        try:
            dir_stat = dir_path.stat()
            dir_mode = stat.filemode(dir_stat.st_mode)
            
            # Check if directory is world-writable
            if stat.S_IWOTH & dir_stat.st_mode:
                findings.append({
                    'title': f'World-Writable Directory: {dir_path}',
                    'severity': 'high',
                    'description': f'Directory {dir_path} is writable by all users',
                    'recommendation': f'Change directory permissions to remove world-write access: chmod 755 {dir_path}',
                    'location': str(dir_path)
                })
            
            # Check if directory is world-readable and in sensitive location
            if stat.S_IROTH & dir_stat.st_mode:
                sensitive_paths = ['/etc', '/home', '/root', '/var', '/opt']
                if any(str(dir_path).startswith(sp) for sp in sensitive_paths):
                    findings.append({
                        'title': f'Sensitive Directory World-Readable: {dir_path}',
                        'severity': 'medium',
                        'description': f'Sensitive directory {dir_path} is readable by all users',
                        'recommendation': f'Consider restricting directory permissions: chmod 750 {dir_path}',
                        'location': str(dir_path)
                    })
        
        except (OSError, PermissionError) as e:
            logger.debug(f"Could not check directory security for {dir_path}: {e}")
        
        return findings
    
    def _check_file_security(self, file_path: Path) -> List[Dict[str, Any]]:
        """Check file security settings.
        
        Args:
            file_path: File path to check
            
        Returns:
            List of security findings for the file
        """
        findings = []
        
        try:
            # Skip if file is too large
            file_stat = file_path.stat()
            if file_stat.st_size > self.max_file_size:
                return findings
            
            # Check file permissions
            file_mode = stat.filemode(file_stat.st_mode)
            
            # Check if file is world-writable
            if stat.S_IWOTH & file_stat.st_mode:
                findings.append({
                    'title': f'World-Writable File: {file_path}',
                    'severity': 'high',
                    'description': f'File {file_path} is writable by all users',
                    'recommendation': f'Change file permissions to remove world-write access: chmod 644 {file_path}',
                    'location': str(file_path)
                })
            
            # Check if file is in a sensitive location and world-readable
            if stat.S_IROTH & file_stat.st_mode:
                sensitive_extensions = ['.pem', '.key', '.crt', '.cert', '.config', '.conf', '.env', '.secret', '.passwd', '.shadow']
                if file_path.suffix.lower() in sensitive_extensions:
                    findings.append({
                        'title': f'Sensitive File World-Readable: {file_path}',
                        'severity': 'high',
                        'description': f'Sensitive file {file_path} is readable by all users',
                        'recommendation': f'Change file permissions to restrict access: chmod 600 {file_path}',
                        'location': str(file_path)
                    })
            
            # Check if file is executable and in unexpected location
            if stat.S_IXUSR & file_stat.st_mode:
                common_exec_paths = ['/usr/bin', '/usr/local/bin', '/bin', '/sbin', '/usr/sbin']
                if not any(str(file_path.parent).startswith(path) for path in common_exec_paths):
                    findings.append({
                        'title': f'Unexpected Executable File: {file_path}',
                        'severity': 'medium',
                        'description': f'File {file_path} is executable but not in a standard binary directory',
                        'recommendation': f'Review if this file should be executable',
                        'location': str(file_path)
                    })
            
            # Check for hidden files if enabled
            if self.check_hidden_files and file_path.name.startswith('.'):
                findings.append({
                    'title': f'Hidden File: {file_path}',
                    'severity': 'low',
                    'description': f'Hidden file found: {file_path}',
                    'recommendation': f'Review hidden file for security implications',
                    'location': str(file_path)
                })
            
            # Check for suspicious file extensions
            suspicious_extensions = [
                '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js', '.jar', 
                '.sh', '.pl', '.py', '.rb', '.php', '.jsp', '.war', '.ear'
            ]
            
            if file_path.suffix.lower() in suspicious_extensions:
                # Check if file is in unexpected location
                expected_script_paths = ['/usr/bin', '/usr/local/bin', '/bin', '/sbin', '/usr/sbin', '/etc/init.d']
                if not any(str(file_path.parent).startswith(path) for path in expected_script_paths):
                    findings.append({
                        'title': f'Suspicious File in Unexpected Location: {file_path}',
                        'severity': 'medium',
                        'description': f'Potentially executable file {file_path} in unexpected location',
                        'recommendation': f'Review file for legitimacy',
                        'location': str(file_path)
                    })
            
            # Check for files with setuid/setgid bits
            if stat.S_ISUID & file_stat.st_mode:
                findings.append({
                    'title': f'File with SetUID Bit: {file_path}',
                    'severity': 'high',
                    'description': f'File {file_path} has SetUID bit set - can be security risk',
                    'recommendation': f'Review if SetUID bit is necessary',
                    'location': str(file_path)
                })
            
            if stat.S_ISGID & file_stat.st_mode:
                findings.append({
                    'title': f'File with SetGID Bit: {file_path}',
                    'severity': 'high',
                    'description': f'File {file_path} has SetGID bit set - can be security risk',
                    'recommendation': f'Review if SetGID bit is necessary',
                    'location': str(file_path)
                })
        
        except (OSError, PermissionError) as e:
            logger.debug(f"Could not check file security for {file_path}: {e}")
        
        return findings
    
    def _check_file_content(self, file_path: Path) -> List[Dict[str, Any]]:
        """Check file content for security issues.
        
        Args:
            file_path: File path to check
            
        Returns:
            List of security findings for the file content
        """
        findings = []
        
        try:
            # Only check text files
            if file_path.suffix.lower() in ['.txt', '.conf', '.config', '.env', '.yml', '.yaml', '.json', '.xml', '.log', '.']:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(10240)  # Read first 10KB to avoid large files
                    
                    # Check for potential secrets in common formats
                    secret_patterns = [
                        (r'password\s*=\s*["\']([^"\']{6,})["\']', 'Password in config file'),
                        (r'api[_-]?key\s*=\s*["\']([^"\']{10,})["\']', 'API Key in config file'),
                        (r'secret[_-]?key\s*=\s*["\']([^"\']{10,})["\']', 'Secret Key in config file'),
                        (r'access[_-]?token\s*=\s*["\']([^"\']{10,})["\']', 'Access Token in config file'),
                        (r'authorization\s*:\s*bearer\s+([a-zA-Z0-9_\-\.]{20,})', 'Authorization token in file'),
                        (r'BEGIN\s+(RSA\s+|EC\s+|PGP\s+|SSH\s+|OPENSSH\s+)?PRIVATE\s+KEY', 'Private key in text file'),
                    ]
                    
                    for pattern, description in secret_patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        if matches:
                            findings.append({
                                'title': f'Potential Secret Found: {file_path.name}',
                                'severity': 'critical',
                                'description': f'{description} found in {file_path}',
                                'recommendation': f'Remove sensitive information from {file_path} and use secure storage',
                                'location': str(file_path)
                            })
                            break  # Only report the first type of secret found
        
        except (OSError, PermissionError, UnicodeDecodeError) as e:
            logger.debug(f"Could not check file content for {file_path}: {e}")
        
        return findings
    
    def scan_suid_files(self) -> List[Dict[str, Any]]:
        """Scan for SUID/SGID files in the system.
        
        Returns:
            List of SUID/SGID files found
        """
        findings = []
        
        try:
            # Use find command to locate SUID/SGID files
            result = subprocess.run(
                ['find', '/', '-perm', '-4000', '-type', 'f', '-print'],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                suid_files = result.stdout.strip().split('\n')
                for file_path in suid_files:
                    if file_path and file_path != '':
                        findings.append({
                            'title': f'SUID File: {file_path}',
                            'severity': 'medium',
                            'description': f'SUID file found: {file_path}',
                            'recommendation': f'Review if SUID bit is necessary for {file_path}',
                            'location': file_path
                        })
            
            # Find SGID files
            result = subprocess.run(
                ['find', '/', '-perm', '-2000', '-type', 'f', '-print'],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                sgid_files = result.stdout.strip().split('\n')
                for file_path in sgid_files:
                    if file_path and file_path != '':
                        findings.append({
                            'title': f'SGID File: {file_path}',
                            'severity': 'medium',
                            'description': f'SGID file found: {file_path}',
                            'recommendation': f'Review if SGID bit is necessary for {file_path}',
                            'location': file_path
                        })
        
        except subprocess.TimeoutExpired:
            logger.warning("SUID/SGID scan timed out")
        except Exception as e:
            logger.error(f"Error scanning for SUID/SGID files: {e}")
        
        return findings
    
    def scan_writable_system_files(self) -> List[Dict[str, Any]]:
        """Scan for world-writable system files.
        
        Returns:
            List of world-writable system files found
        """
        findings = []
        
        try:
            # Define system directories to check
            system_dirs = ['/etc', '/bin', '/sbin', '/usr/bin', '/usr/sbin', '/lib', '/usr/lib']
            
            for sys_dir in system_dirs:
                if os.path.exists(sys_dir):
                    for root, dirs, files in os.walk(sys_dir):
                        for file in files:
                            file_path = os.path.join(root, file)
                            try:
                                file_stat = os.stat(file_path)
                                # Check if world-writable
                                if stat.S_IWOTH & file_stat.st_mode:
                                    findings.append({
                                        'title': f'World-Writable System File: {file_path}',
                                        'severity': 'high',
                                        'description': f'System file {file_path} is world-writable',
                                        'recommendation': f'Change file permissions to remove world-write access',
                                        'location': file_path
                                    })
                            except (OSError, PermissionError):
                                continue
        
        except Exception as e:
            logger.error(f"Error scanning for writable system files: {e}")
        
        return findings


# For compatibility
import time