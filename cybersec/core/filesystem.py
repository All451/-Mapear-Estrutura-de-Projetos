"""Filesystem scanner module for the cybersecurity toolkit."""
import os
import stat
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional


class FilesystemScanner:
    """Scanner for filesystem security checks."""

    def __init__(self):
        """Initialize the filesystem scanner."""
        self.suspicious_files = []
        self.world_writable_dirs = []
        self.suid_files = []
        self.logger = logging.getLogger(__name__)

    def find_suspicious_files(self, base_path: str, max_depth: int = 3) -> List[Dict[str, Any]]:
        """
        Find suspicious files in the filesystem.
        
        Args:
            base_path: Base path to start scanning
            max_depth: Maximum directory depth to scan
            
        Returns:
            List of suspicious files with details
        """
        suspicious_files = []
        
        try:
            for root, dirs, files in os.walk(base_path):
                # Calculate current depth
                current_depth = root[len(base_path):].count(os.sep)
                if current_depth >= max_depth:
                    # Don't traverse deeper
                    del dirs[:]
                
                for file in files:
                    filepath = os.path.join(root, file)
                    try:
                        file_stat = os.stat(filepath)
                        
                        # Check for world-writable files
                        if file_stat.st_mode & stat.S_IWOTH:  # World writable
                            file_info = {
                                'path': filepath,
                                'size': file_stat.st_size,
                                'permissions': oct(file_stat.st_mode)[-3:],
                                'modified': datetime.fromtimestamp(file_stat.st_mtime).isoformat()
                            }
                            suspicious_files.append(file_info)
                        
                        # Check for executable files in unusual locations
                        if file_stat.st_mode & stat.S_IXUSR and 'tmp' in filepath.lower():
                            file_info = {
                                'path': filepath,
                                'size': file_stat.st_size,
                                'permissions': oct(file_stat.st_mode)[-3:],
                                'modified': datetime.fromtimestamp(file_stat.st_mtime).isoformat()
                            }
                            suspicious_files.append(file_info)
                    except (OSError, PermissionError):
                        # Skip files we can't access
                        continue
        except Exception as e:
            self.logger.error(f"Error finding suspicious files: {e}")
        
        return suspicious_files

    def find_world_writable_directories(self, base_path: str, max_depth: int = 3) -> List[str]:
        """
        Find world-writable directories in the filesystem.
        
        Args:
            base_path: Base path to start scanning
            max_depth: Maximum directory depth to scan
            
        Returns:
            List of world-writable directory paths
        """
        world_writable_dirs = []
        
        try:
            for root, dirs, files in os.walk(base_path):
                # Calculate current depth
                current_depth = root[len(base_path):].count(os.sep)
                if current_depth >= max_depth:
                    # Don't traverse deeper
                    del dirs[:]
                
                for dir_name in dirs:
                    dir_path = os.path.join(root, dir_name)
                    try:
                        dir_stat = os.stat(dir_path)
                        if dir_stat.st_mode & stat.S_IWOTH:  # World writable
                            world_writable_dirs.append(dir_path)
                    except (OSError, PermissionError):
                        # Skip directories we can't access
                        continue
        except Exception as e:
            self.logger.error(f"Error finding world-writable directories: {e}")
        
        return world_writable_dirs

    def find_suid_files(self, base_path: str, max_depth: int = 3) -> List[str]:
        """
        Find files with SUID bit set in the filesystem.
        
        Args:
            base_path: Base path to start scanning
            max_depth: Maximum directory depth to scan
            
        Returns:
            List of SUID file paths
        """
        suid_files = []
        
        try:
            for root, dirs, files in os.walk(base_path):
                # Calculate current depth
                current_depth = root[len(base_path):].count(os.sep)
                if current_depth >= max_depth:
                    # Don't traverse deeper
                    del dirs[:]
                
                for file in files:
                    filepath = os.path.join(root, file)
                    try:
                        file_stat = os.stat(filepath)
                        if file_stat.st_mode & stat.S_ISUID:  # SUID bit set
                            suid_files.append(filepath)
                    except (OSError, PermissionError):
                        # Skip files we can't access
                        continue
        except Exception as e:
            self.logger.error(f"Error finding SUID files: {e}")
        
        return suid_files

    def find_recent_files(self, base_path: str, hours: int = 24, max_depth: int = 3) -> List[Dict[str, Any]]:
        """
        Find files modified recently.
        
        Args:
            base_path: Base path to start scanning
            hours: Number of hours back to check
            max_depth: Maximum directory depth to scan
            
        Returns:
            List of recently modified files with details
        """
        recent_files = []
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        try:
            for root, dirs, files in os.walk(base_path):
                # Calculate current depth
                current_depth = root[len(base_path):].count(os.sep)
                if current_depth >= max_depth:
                    # Don't traverse deeper
                    del dirs[:]
                
                for file in files:
                    filepath = os.path.join(root, file)
                    try:
                        file_stat = os.stat(filepath)
                        mod_time = datetime.fromtimestamp(file_stat.st_mtime)
                        
                        if mod_time > cutoff_time:
                            file_info = {
                                'path': filepath,
                                'size': file_stat.st_size,
                                'modified': mod_time.isoformat(),
                                'permissions': oct(file_stat.st_mode)[-3:]
                            }
                            recent_files.append(file_info)
                    except (OSError, PermissionError):
                        # Skip files we can't access
                        continue
        except Exception as e:
            self.logger.error(f"Error finding recent files: {e}")
        
        return recent_files

    def scan(self, base_path: str = '/tmp') -> Dict[str, Any]:
        """
        Perform a complete filesystem security scan.
        
        Args:
            base_path: Base path to scan (default: /tmp)
            
        Returns:
            Dictionary containing filesystem scan results
        """
        self.logger.info(f"Starting filesystem scan of {base_path}...")
        
        results = {
            'suspicious_files': self.find_suspicious_files(base_path),
            'world_writable_dirs': self.find_world_writable_directories(base_path),
            'suid_files': self.find_suid_files(base_path),
            'recent_files': self.find_recent_files(base_path)
        }
        
        self.logger.info("Filesystem scan completed.")
        return results