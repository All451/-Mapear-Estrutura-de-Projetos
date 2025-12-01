# Cybersecurity Modules

This repository contains four cybersecurity modules designed for system security monitoring and management:

## 1. Cybersecurity Module (`cybersecurity_module.py`)

A general security module that provides basic cybersecurity utilities:

- Security audit functions
- System integrity checking
- Security event logging

### Functions:
- `security_audit()` - Performs basic security audit
- `check_system_integrity()` - Checks system integrity
- `log_security_event(event_type, description)` - Logs security events

## 2. UFW Port Verification Module (`ufw_port_checker.py`)

A module to check open ports using UFW (Uncomplicated Firewall):

- Check UFW status
- List open ports
- Check if specific port is open
- Port security advice

### Functions:
- `check_ufw_status()` - Returns UFW status
- `list_open_ports()` - Lists all open ports
- `is_port_open(port_number)` - Checks if a specific port is open
- `scan_for_open_ports()` - Scans and returns all open ports
- `check_port_security(port_number)` - Checks security status of a port

## 3. fban2 Firewall Ban System (`fban2.py`)

A comprehensive firewall ban system for managing IP bans:

- Ban/unban IP addresses
- Auto-ban from log analysis
- Track ban status and history
- Support for both iptables and UFW

### Features:
- `FBan2.ban_ip(ip, reason, duration)` - Ban an IP address
- `FBan2.unban_ip(ip)` - Unban an IP address
- `FBan2.check_ip_status(ip)` - Check if IP is banned
- `FBan2.list_banned_ips()` - List all banned IPs
- `FBan2.auto_ban_from_logs(log_file, threshold, time_window)` - Auto-ban based on log analysis

## 4. Docker Exposure Checker (`docker_exposure_checker.py`)

A module to verify if Docker containers are exposed to the internet:

- Scan running containers for exposed ports
- Check if ports are accessible internally and externally
- Identify services running on exposed ports
- Generate security recommendations
- Risk level assessment

### Functions:
- `DockerExposureChecker.scan_exposed_containers()` - Scan for exposed containers
- `DockerExposureChecker.generate_report()` - Generate human-readable report
- `DockerExposureChecker.get_security_recommendations()` - Get security recommendations

## 5. Security Suite (`security_suite.py`)

Main module that integrates all security modules with a command-line interface:

- General Security Audit
- UFW Port Verification
- Firewall Ban Management
- Docker Container Exposure Check
- Complete Security Scan

### Usage:
```bash
python3 security_suite.py
```

## Requirements

- Python 3.x
- UFW (optional, for port checking and firewall management)
- iptables (for fallback firewall management)
- Docker (for container exposure checking)
- docker python library (`pip install docker`)
- requests python library (`pip install requests`)

## Installation

No special installation required. Just run the modules directly with Python:

```bash
python3 security_suite.py
```

For individual modules:
```bash
python3 cybersecurity_module.py
python3 ufw_port_checker.py
python3 fban2.py
python3 docker_exposure_checker.py
```