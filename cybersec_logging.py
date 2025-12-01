"""
Cybersecurity Toolkit Logging System
This module provides structured logging for the cybersecurity toolkit.
"""
import logging
import os
from datetime import datetime
from logging.handlers import RotatingFileHandler


class CybersecLogger:
    """
    Structured logging system for the cybersecurity toolkit
    """
    
    def __init__(self, name: str = "cybersec", log_file: str = "/tmp/cybersec.log", 
                 level: str = "INFO", force_new: bool = False):
        """
        Initialize the logging system
        
        Args:
            name: Name of the logger
            log_file: Path to the log file
            level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            force_new: If True, removes existing handlers to create a fresh logger
        """
        self.logger = logging.getLogger(name)
        
        # Set the logging level
        level = getattr(logging, level.upper(), logging.INFO)
        self.logger.setLevel(level)
        
        # If force_new is True, remove existing handlers
        if force_new:
            self.logger.handlers.clear()
        
        # Prevent adding multiple handlers if logger already exists
        if not self.logger.handlers:
            # Create file handler with rotation - use a location that's definitely writable
            try:
                file_handler = RotatingFileHandler(
                    log_file,
                    maxBytes=10485760,  # 10MB
                    backupCount=5
                )
            except PermissionError:
                # Fallback to a different location if /tmp is not writable
                fallback_log_file = "./cybersec.log"
                file_handler = RotatingFileHandler(
                    fallback_log_file,
                    maxBytes=10485760,  # 10MB
                    backupCount=5
                )
            
            # Create console handler
            console_handler = logging.StreamHandler()
            
            # Create formatter
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            
            file_handler.setFormatter(formatter)
            console_handler.setFormatter(formatter)
            
            # Add handlers to logger
            self.logger.addHandler(file_handler)
            self.logger.addHandler(console_handler)
    
    def get_logger(self):
        """
        Get the configured logger instance
        
        Returns:
            Configured logger instance
        """
        return self.logger
    
    def log_security_event(self, event_type: str, description: str, 
                          severity: str = "INFO", ip_address: str = None, 
                          source: str = None):
        """
        Log a security-related event with additional context
        
        Args:
            event_type: Type of security event (e.g., 'scan', 'ban', 'alert')
            description: Description of the event
            severity: Severity level (INFO, WARNING, ERROR, CRITICAL)
            ip_address: IP address related to the event (if applicable)
            source: Source of the event (if applicable)
        """
        extra_info = []
        if ip_address:
            extra_info.append(f"IP: {ip_address}")
        if source:
            extra_info.append(f"Source: {source}")
        
        extra_str = f" [{' | '.join(extra_info)}]" if extra_info else ""
        message = f"[SECURITY] {event_type}: {description}{extra_str}"
        
        severity_level = getattr(logging, severity.upper(), logging.INFO)
        self.logger.log(severity_level, message)
    
    def log_scan_result(self, scan_type: str, target: str, 
                       findings: list = None, status: str = "completed"):
        """
        Log the results of a security scan
        
        Args:
            scan_type: Type of scan (e.g., 'network', 'filesystem', 'docker')
            target: Target of the scan
            findings: List of findings from the scan
            status: Status of the scan (completed, failed, partial)
        """
        if findings:
            message = f"[SCAN] {scan_type} scan on {target} {status} with {len(findings)} finding(s)"
        else:
            message = f"[SCAN] {scan_type} scan on {target} {status} with no findings"
        
        self.logger.info(message)
        
        if findings:
            for finding in findings:
                self.logger.info(f"  - {finding}")
    
    def log_firewall_action(self, action: str, ip: str, reason: str = ""):
        """
        Log firewall-related actions
        
        Args:
            action: Action taken (e.g., 'ban', 'unban', 'check')
            ip: IP address affected
            reason: Reason for the action
        """
        message = f"[FIREWALL] {action.upper()} IP: {ip}"
        if reason:
            message += f" - Reason: {reason}"
        
        self.logger.info(message)


def setup_logging(name: str = "cybersec", log_file: str = "/tmp/cybersec.log", 
                  level: str = "INFO") -> CybersecLogger:
    """
    Convenience function to set up logging
    
    Args:
        name: Name of the logger
        log_file: Path to the log file
        level: Logging level
        
    Returns:
        Configured CybersecLogger instance
    """
    return CybersecLogger(name, log_file, level)


if __name__ == "__main__":
    # Example usage
    logger = setup_logging()
    
    # Log different types of events
    logger.log_security_event("port_scan", "Detected open port 22 on localhost", "INFO", "127.0.0.1")
    logger.log_security_event("intrusion_attempt", "Multiple failed login attempts", "WARNING", "192.168.1.100", "SSH")
    logger.log_scan_result("network", "192.168.1.0/24", ["Port 22 open", "Port 80 open"], "completed")
    logger.log_firewall_action("ban", "10.0.0.5", "Multiple failed authentication attempts")
    
    print(f"Logging system initialized. Check {logger.get_logger().handlers[0].baseFilename} for logs.")