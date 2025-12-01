# 🛡️ Comprehensive Cybersecurity Toolkit Guide

Welcome to the most powerful cybersecurity toolkit ever created! This comprehensive suite integrates multiple security modules to provide you with a complete security analysis and protection platform.

## 🚀 Overview

The Cybersecurity Toolkit is a multi-layered security solution that combines:

1. **System Integrity Analysis** - Deep system security checks
2. **Network Security** - Firewall and port monitoring
3. **Firewall Management** - IP banning/unbanning system
4. **Docker Security** - Container exposure detection
5. **File System Security** - Sensitive file detection
6. **Threat Intelligence** - Integration-ready threat feeds

## 📋 Available Tools

### 1. Main Cybersecurity Suite
- **Python Version**: `cybersecurity_suite.py` - Full-featured with advanced analysis
- **Shell Version**: `cybersecurity_suite.sh` - Lightweight, system-compatible version
- **Main Entry Point**: `cybersec_toolkit.py` - Smart router between versions

### 2. Individual Security Modules
- `cybersecurity_module.py` / `cybersecurity_module.sh` - Core security functions
- `ufw_port_checker.py` / `ufw_port_checker.sh` - Network security analysis
- `fban2.py` / `fban2.sh` - Firewall ban management system
- `docker_exposure_checker.py` / `docker_exposure_checker.sh` - Container security
- `mapear_estrutura_ciberseg.sh` - Directory structure mapping with security focus

## 🛠️ Quick Start

### Run the Main Toolkit
```bash
# Interactive mode (default)
./run_cybersec_toolkit.sh

# Or directly
python3 cybersec_toolkit.py

# Comprehensive security scan
python3 cybersec_toolkit.py --scan

# Interactive mode
python3 cybersec_toolkit.py --interactive
# or
python3 cybersec_toolkit.py -i
```

### Direct Module Usage
```bash
# Run comprehensive scan directly
python3 cybersecurity_suite.py --scan

# Use shell version
bash cybersecurity_suite.sh --scan

# Use individual modules
python3 security_suite.py
bash security_suite.sh
```

## 🎯 Key Features

### 1. Comprehensive Security Scanning
- **System Integrity Check**: Detects security misconfigurations and vulnerabilities
- **Network Security Analysis**: Identifies open ports and potential attack vectors
- **File System Security**: Scans for sensitive files and weak permissions
- **Docker Container Security**: Checks for exposed containers and services
- **Firewall Status**: Reviews current firewall configuration and active bans

### 2. Real-time Threat Management
- **IP Banning System**: Block malicious IPs automatically or manually
- **Log Analysis**: Detect suspicious activities from system logs
- **Process Monitoring**: Identify potentially malicious processes
- **Threat Intelligence Ready**: Integration points for threat feeds

### 3. Advanced Security Features
- **Directory Mapping with Security Focus**: Identifies sensitive files and weak permissions
- **Network Exposure Assessment**: Determines if services are accessible externally
- **Risk Level Assessment**: Classifies security risks by severity
- **Automated Security Recommendations**: Provides actionable security advice

## 🧰 Detailed Usage

### Python Suite Options
```bash
# Show version
python3 cybersecurity_suite.py --version

# Run comprehensive scan
python3 cybersecurity_suite.py --scan

# Interactive mode
python3 cybersecurity_suite.py --interactive
# or
python3 cybersecurity_suite.py -i

# Help
python3 cybersecurity_suite.py --help
```

### Shell Suite Options
```bash
# Interactive mode
bash cybersecurity_suite.sh

# Help
bash cybersecurity_suite.sh --help
```

### Individual Module Usage

#### Firewall Management (fban2)
```bash
# Ban an IP
python3 fban2.py ban 192.168.1.100 "Suspicious activity"

# Unban an IP
python3 fban2.py unban 192.168.1.100

# Check IP status
python3 fban2.py status 192.168.1.100

# List banned IPs
python3 fban2.py list
```

#### Docker Security Check
```bash
python3 docker_exposure_checker.py
```

#### Directory Security Mapping
```bash
# With security focus
./mapear_estrutura_ciberseg.sh --security -s -p -a /path/to/directory

# Export to markdown with security alerts
./mapear_estrutura_ciberseg.sh --security -f markdown /var/www > security_report.md
```

## 🔐 Security Best Practices

### 1. Regular Scanning
- Schedule regular comprehensive scans
- Monitor for new open ports
- Check for sensitive files regularly
- Review firewall logs frequently

### 2. Access Control
- Implement principle of least privilege
- Regularly audit user accounts
- Use strong authentication methods
- Monitor failed login attempts

### 3. Network Security
- Close unnecessary ports
- Implement network segmentation
- Use VPNs for remote access
- Monitor network traffic patterns

### 4. Incident Response
- Have a documented response plan
- Regularly test incident procedures
- Maintain system backups
- Document security events

## 📊 Sample Output

The toolkit provides detailed reports like this:

```
============================================================
CYBERSECURITY COMPREHENSIVE SCAN
============================================================

[1/6] Running System Integrity Check...
  - Checking system for common security issues...
  - Checking system integrity...
  - No suspicious processes detected
  - No suspicious authentication events found in recent logs

[2/6] Running Network Security Check...
  - Found 3 open ports via UFW
    Port 22 (tcp) - enabled
    Port 80 (tcp) - enabled
    Port 443 (tcp) - enabled
  - No commonly vulnerable ports detected

[3/6] Running Firewall Analysis...
  - UFW Status:
    Status: active
    Logging: on (low)
    Default: deny (incoming), allow (outgoing), disabled (routed)
    ...

[4/6] Running Docker Container Exposure Check...
  - Docker exposure report:
  No exposed Docker containers found.

[5/6] Running File System Security Check...
  - Scanning for sensitive files...
  - No sensitive files detected in current directory

[6/6] Checking Active Firewall Bans...
  - Total banned IPs: 0

============================================================
COMPREHENSIVE SECURITY REPORT
============================================================

SUMMARY:
  - System integrity: CHECKED
  - Network security: CHECKED
  - Firewall status: CHECKED
  - Docker exposure: CHECKED
  - File system security: CHECKED
  - Active bans: CHECKED

RECOMMENDATIONS:
  - Review all open ports and close unnecessary ones
  - Regularly update system packages
  - Monitor system logs for suspicious activity
  - Implement strong password policies
  - Use fail2ban or similar tools for automatic blocking
  - Regular security audits
```

## 🛡️ Advanced Configuration

### Custom Security Scripts
The toolkit is designed to be extensible. You can create custom security scripts by importing the main classes:

```python
from cybersecurity_suite import CybersecuritySuite

# Create a custom security scanner
suite = CybersecuritySuite()

# Run specific security checks
suite.system_integrity_scan()
suite.network_security_scan()
```

### Integration with Security Pipelines
The toolkit can be integrated into CI/CD pipelines and security automation workflows:

```bash
# Example: Add to your security pipeline
if python3 cybersecurity_suite.py --scan | grep -q "WARNING\|CRITICAL"; then
    echo "Security issues detected! Halting deployment."
    exit 1
fi
```

## 📞 Support and Community

### Getting Help
- Check the individual README files for specific modules
- Review the source code documentation
- Create an issue in the repository for bugs or feature requests

### Contributing
We welcome contributions to improve the toolkit:
- Bug fixes and security patches
- New security modules
- Enhanced reporting features
- Integration with additional security tools

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Important Disclaimer

This cybersecurity toolkit is designed for legitimate security testing, system hardening, and security research. 

**Use responsibly and ethically:**
- Only use on systems you own or have explicit permission to test
- Always comply with applicable laws and regulations
- Respect privacy and data protection requirements
- Obtain proper authorization before testing any system
- Use the toolkit to improve security, not to cause harm

The creators and contributors are not responsible for any misuse of this toolkit.

---

🛡️ **Stay Secure!** 🛡️

*The most powerful cybersecurity toolkit at your fingertips.*