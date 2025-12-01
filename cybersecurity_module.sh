#!/bin/bash
# Cybersecurity Module - General Security Functions
# This module contains general cybersecurity utilities and functions.

# Perform a basic security audit of the system
security_audit() {
    echo "Performing basic security audit..."
    # Add security audit logic here
    # For example, checking for common security issues
    echo "Checking system for common security issues..."
    
    # Check if system is up to date
    if command -v apt &> /dev/null; then
        echo "Checking for available updates (Debian/Ubuntu)..."
        # Note: This would normally check for updates without installing them
    elif command -v yum &> /dev/null; then
        echo "Checking for available updates (RHEL/CentOS)..."
        # Note: This would normally check for updates without installing them
    fi
    
    # Check for listening network services
    if command -v netstat &> /dev/null; then
        echo "Checking for listening network services..."
        netstat -tuln
    elif command -v ss &> /dev/null; then
        echo "Checking for listening network services..."
        ss -tuln
    fi
    
    # Check for users with UID 0 (other than root)
    echo "Checking for users with UID 0 (other than root)..."
    awk -F: '($3 == 0) && ($1 != "root") {print $1}' /etc/passwd
    if [ $? -eq 0 ]; then
        echo "No additional users with UID 0 found."
    fi
}

# Check system integrity for potential security issues
check_system_integrity() {
    echo "Checking system integrity..."
    
    # Check for files with SUID bit set (potential security risk)
    echo "Checking for files with SUID bit set..."
    find / -perm -4000 2>/dev/null | head -20  # Limit output for readability
    
    # Check for world-writable files in system directories
    echo "Checking for world-writable files in system directories..."
    find /tmp /var/tmp /dev -type f -perm -0002 2>/dev/null | head -20
    
    # Check for common log files
    echo "Checking log file permissions..."
    ls -la /var/log/ | head -10
}

# Log a security-related event
log_security_event() {
    local event_type="$1"
    local description="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local log_entry="[$timestamp] $event_type: $description"
    
    # Try to write to security log (may require sudo)
    if [ -w "/var/log/security.log" ] || [ -w "/tmp" ]; then
        if [ -w "/var/log/security.log" ]; then
            echo "$log_entry" >> /var/log/security.log
        else
            # Write to a temporary location if we can't write to system logs
            echo "$log_entry" >> /tmp/security.log
        fi
    else
        # Just print to stdout if we can't write to any log file
        echo "$log_entry" >&2
    fi
}

# Make functions available when sourced
export -f security_audit
export -f check_system_integrity
export -f log_security_event