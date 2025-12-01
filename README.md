# 🛡️ Cybersecurity Toolkit

[![Version](https://img.shields.io/badge/version-3.0.0-blue)](VERSION)
[![Python](https://img.shields.io/badge/python-3.8+-green)](requirements.txt)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

> A comprehensive cybersecurity toolkit for system analysis, network security, firewall management, and threat detection

## 📋 Table of Contents
- [About](#about)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Modules](#modules)
- [CLI Interface](#cli-interface)
- [Configuration](#configuration)
- [Examples](#examples)
- [Development](#development)

## 📌 About

The Cybersecurity Toolkit is a comprehensive security solution that integrates multiple security modules for comprehensive system analysis and protection. It combines the power of both Python and Shell implementations to provide:

- **System Analysis**: Integrity checking, process monitoring, log analysis
- **Network Security**: UFW firewall status, open port detection, vulnerability assessment
- **Firewall Management**: IP banning/unbanning with fban2
- **Container Security**: Docker exposure detection
- **File System Security**: Sensitive file detection and permission analysis

## ✅ Features

### 🔍 System Analysis
- System integrity checking
- Process monitoring for suspicious activities
- Log analysis for security events
- Security audit capabilities

### 🌐 Network Security
- UFW firewall status monitoring
- Open port detection and analysis
- Vulnerable port identification
- Network exposure assessment

### 🛡️ Firewall Management
- Advanced IP banning/unbanning (fban2)
- Automatic ban from log analysis
- Ban status tracking
- Support for iptables and UFW

### 🐳 Container Security
- Docker container exposure detection
- Port accessibility testing
- Service identification
- Risk level assessment

### 📁 File System Security
- Sensitive file detection (.env, config files, keys, etc.)
- Weak permission identification
- Security issue scanning
- Directory structure mapping with security analysis

### 📊 Reporting & Intelligence
- Comprehensive security reports
- Automated recommendations
- Threat intelligence ready
- Multi-format output (JSON, Markdown, plain text)

## ⚙️ Installation

### Prerequisites
```bash
# Install required dependencies
sudo apt update
sudo apt install tree jq python3 python3-pip -y
```

### Setup
```bash
# Clone or download the repository
# Make scripts executable
chmod +x *.sh *.py

# Install Python dependencies (if any)
pip3 install -r requirements.txt
```

## 🚀 Usage

### Quick Start
```bash
# Run the complete toolkit
./run_cybersec_toolkit.sh

# Or directly with Python
python3 cybersec_toolkit.py

# Comprehensive scan
python3 cybersec_toolkit.py --scan

# Interactive mode
python3 cybersec_toolkit.py -i

# Shell version
bash cybersecurity_suite.sh
```

### Command Line Options
| Option | Description |
|--------|-------------|
| `--scan` | Run comprehensive security scan |
| `-i`, `--interactive` | Run in interactive mode |
| `-v`, `--version` | Show version information |
| `-h`, `--help` | Show help message |

## 🧩 Modules

The toolkit is organized into several modules:

### Core Security Module
- `cybersecurity_module.py/sh` - Core security functions
- `security_audit()` - Basic security audit
- `check_system_integrity()` - System integrity verification

### Network Security Module
- `ufw_port_checker.py/sh` - UFW and port analysis
- `list_open_ports()` - Identify open ports
- `check_ufw_status()` - Firewall status

### Firewall Management Module
- `fban2.py/sh` - Advanced firewall management
- `ban_ip()` - Ban IP addresses
- `unban_ip()` - Unban IP addresses
- `check_ip_status()` - Check ban status

### Container Security Module
- `docker_exposure_checker.py/sh` - Docker security
- `DockerExposureChecker` - Container exposure detection
- Security recommendations for containers

### Directory Mapping Module
- `mapear_estrutura.sh/libmapear.sh` - Security-focused directory mapping
- Multiple output formats (tree, JSON, Markdown, plain)
- Sensitive file detection
- Permission analysis

## 🖥️ CLI Interface

### Interactive Mode
```bash
python3 cybersec_toolkit.py -i
```

The interactive mode provides a menu-driven interface:
1. Run Comprehensive Security Scan
2. Network Security Analysis
3. Firewall Management
4. Docker Container Security
5. File System Security
6. Threat Intelligence Check
7. Exit

### Firewall Management Menu
- Ban an IP address
- Unban an IP address
- Check IP status
- List banned IPs
- Return to main menu

## ⚙️ Configuration

The toolkit can be configured using a configuration file (coming in future versions):

```yaml
# cybersec.config.yaml (planned feature)
general:
  log_level: INFO
  output_format: markdown
  color_output: true

security:
  scan_depth: 2
  include_hidden: false
  check_permissions: true

network:
  ufw_enabled: true
  check_ports: [22, 80, 443, 3306, 5432]

firewall:
  ban_duration: 3600
  auto_ban_threshold: 5
  log_file: /var/log/auth.log

docker:
  check_exposure: true
  internal_networks: [172.17.0.0/16]
```

## 🧪 Examples

### Comprehensive Security Scan
```bash
python3 cybersec_toolkit.py --scan
```

### Interactive Security Analysis
```bash
python3 cybersec_toolkit.py -i
```

### Network Security Check
```bash
python3 cybersecurity_suite.py
# Then select option 2 for network security analysis
```

### Firewall Management
```bash
python3 cybersecurity_suite.py -i
# Then select option 3 for firewall management
```

### Directory Mapping with Security Analysis
```bash
# Map current directory with security checks
./mapear_estrutura.sh --security -a .

# Export to JSON format
./mapear_estrutura.sh --security -f json /etc > etc_analysis.json

# Limit depth and show permissions
./mapear_estrutura.sh --security -l 2 -p /home/user/
```

## 🛠️ Development

### Project Structure
```
cybersec-toolkit/
├── README.md                          # Main documentation
├── VERSION                           # Version file
├── CHANGELOG.md                      # Version history
├── LICENSE                         # License information
├── requirements.txt                 # Python dependencies
├── cybersec_toolkit.py             # Main entry point
├── cybersecurity_suite.py/sh       # Main security suite
├── cybersecurity_module.py/sh      # Core security functions
├── ufw_port_checker.py/sh          # Network security
├── fban2.py/sh                     # Firewall management
├── docker_exposure_checker.py/sh   # Container security
├── mapear_estrutura.sh/libmapear.sh # Directory mapping
├── run_cybersec_toolkit.sh         # Easy run script
└── docs/                           # Additional documentation
```

### Adding New Modules
1. Create a new module file following the naming convention
2. Implement the required functions
3. Import the module in the main suite
4. Add menu options if needed
5. Update documentation

## 🤝 Contributing

Contributions are welcome! Here are some ways you can contribute:

1. **Bug Reports**: Open an issue if you find a bug
2. **Feature Requests**: Suggest new features or improvements
3. **Code Contributions**: Submit pull requests for fixes or features
4. **Documentation**: Improve existing documentation or add new guides
5. **Testing**: Help test and validate the tools

### Development Guidelines
- Follow Python PEP 8 style guidelines
- Write clear, descriptive commit messages
- Include tests for new functionality
- Update documentation for new features
- Ensure backward compatibility when possible

## 📝 Versioning

This project follows Semantic Versioning (SemVer). For the versions available, see the [CHANGELOG.md](CHANGELOG.md).

Current version: `3.0.0`

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🚀 Future Enhancements

Planned improvements for future versions:
- [ ] Automated testing framework
- [ ] Enhanced logging with rotation
- [ ] Configuration file support
- [ ] API endpoints for integration
- [ ] Web dashboard interface
- [ ] Threat intelligence integration
- [ ] Plugin system for custom modules
- [ ] CI/CD integration
- [ ] Docker container for easy deployment

## 📞 Support

If you need help with the toolkit:

1. Check the documentation in this README
2. Review the example usage in the Examples section
3. Look at the source code comments
4. Open an issue in the repository if you find a bug or need a feature