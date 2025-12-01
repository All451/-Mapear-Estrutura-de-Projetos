# 🛡️ Cybersecurity Suite - Powerful Security Analysis Tool

A comprehensive cybersecurity toolkit that integrates multiple security modules for comprehensive system analysis and protection.

## 🚀 Features

### 1. System Integrity Analysis
- Security audit of the system
- System integrity checking
- Process monitoring for suspicious activity
- Log analysis for security events

### 2. Network Security
- UFW firewall status monitoring
- Open port detection and analysis
- Vulnerable port identification
- Network exposure assessment

### 3. Firewall Management (fban2)
- IP address banning/unbanning
- Automatic ban from log analysis
- Ban status tracking
- Support for both iptables and UFW

### 4. Docker Security
- Container exposure detection
- Port accessibility testing
- Service identification
- Risk level assessment

### 5. File System Security
- Sensitive file detection (.env, config files, keys, etc.)
- Weak permission identification
- Security issue scanning

### 6. Threat Intelligence
- Integration-ready with threat feeds
- Malicious IP checking capabilities

## 📋 Requirements

- Python 3.x
- UFW (optional, for port checking and firewall management)
- iptables (for fallback firewall management)
- Docker (for container exposure checking)
- docker python library (`pip install docker`)
- requests python library (`pip install requests`)

## 🛠️ Installation

No special installation required. Just run the suite directly with Python:

```bash
python3 cybersecurity_suite.py
```

Or make it executable:
```bash
chmod +x cybersecurity_suite.py
./cybersecurity_suite.py
```

## 🎯 Usage

### Interactive Mode (Default)
```bash
python3 cybersecurity_suite.py
```

### Comprehensive Security Scan
```bash
python3 cybersecurity_suite.py --scan
```

### Interactive Mode
```bash
python3 cybersecurity_suite.py --interactive
# or
python3 cybersecurity_suite.py -i
```

### Version Information
```bash
python3 cybersecurity_suite.py --version
# or
python3 cybersecurity_suite.py -v
```

## 🧰 Available Tools

### 1. Comprehensive Security Scan
Performs a complete security assessment of your system including:
- System integrity checks
- Network security analysis
- Firewall configuration review
- Docker container exposure check
- File system security assessment
- Active ban status

### 2. Network Security Analysis
- UFW status monitoring
- Open port detection
- Vulnerable port identification
- Network exposure assessment

### 3. Firewall Management
- Ban/unban IP addresses
- Check IP ban status
- List all banned IPs
- Auto-ban from log analysis

### 4. Docker Container Security
- Scan running containers for exposed ports
- Check if ports are accessible internally and externally
- Identify services running on exposed ports
- Generate security recommendations
- Risk level assessment

### 5. File System Security
- Scan for sensitive files (.env, config files, keys, etc.)
- Identify files with weak permissions
- Security issue detection

### 6. Threat Intelligence Check
- Integration with threat intelligence feeds
- Malicious IP and domain checking
- Real-time threat assessment

## 📊 Sample Output

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

## 🔐 Security Best Practices

1. **Regular Scanning**: Run comprehensive scans regularly to identify security issues
2. **Port Management**: Close unnecessary ports and restrict access to essential ones
3. **Log Monitoring**: Monitor system logs for suspicious activity
4. **Access Control**: Implement strong access controls and authentication
5. **Update Management**: Keep all systems and packages updated
6. **Network Segmentation**: Use proper network segmentation to limit exposure

## 🛡️ Advanced Usage

### Custom Security Scripts
The suite can be extended with custom security scripts by importing the main classes:

```python
from cybersecurity_suite import CybersecuritySuite

suite = CybersecuritySuite()
suite.run_comprehensive_scan()
```

### Integration with CI/CD
The tool can be integrated into CI/CD pipelines for automated security testing.

## 📞 Support

For support, questions, or contributions, please open an issue in the repository.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is designed for security testing and system hardening. Use responsibly and only on systems you own or have explicit permission to test. Always comply with applicable laws and regulations.