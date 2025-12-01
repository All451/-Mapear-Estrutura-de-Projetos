# Cybersecurity Toolkit

## Description
The Cybersecurity Toolkit is a comprehensive set of cybersecurity tools for Linux systems, designed for security auditing, network monitoring, firewall management, and Docker container security verification.

## Features
- **System Scanning**: Check permissions, suspicious files, and insecure configurations
- **Network Analysis**: Detection of open ports, exposed services, and network vulnerabilities
- **Firewall Management**: IP banning system with UFW and iptables
- **Docker Security**: Container security configuration verification
- **Professional Reports**: Report generation in multiple formats (Markdown, JSON, HTML, TXT)

## Installation

### Prerequisites
- Python 3.8+
- Linux (Ubuntu 20.04+, Debian 11+, CentOS 8+)
- Sudo permissions for firewall operations
- UFW (Uncomplicated Firewall) installed
- Docker (optional, for container verification)

### Installation
```bash
git clone https://github.com/example/cybersec-toolkit.git
cd cybersec-toolkit
pip install -r requirements.txt
python setup.py install
```

## Usage

### Basic Commands
```bash
# Show version
cybersec --version

# Show help
cybersec --help

# Full scan
cybersec scan --full

# Check firewall status
cybersec firewall status

# Analyze network
cybersec network analyze

# Scan Docker containers
cybersec docker scan
```

### Scan Commands
```bash
# Quick scan
cybersec scan --quick

# System only
cybersec scan --system

# Network only
cybersec scan --network

# Filesystem only
cybersec scan --filesystem [PATH]

# Docker only
cybersec scan --docker
```

### Firewall Commands
```bash
# Ban IP
cybersec firewall ban 192.168.1.100 --reason "Suspected attack"

# Unban IP
cybersec firewall unban 192.168.1.100

# List banned IPs
cybersec firewall list

# Check IP status
cybersec firewall check 192.168.1.100
```

### Network Commands
```bash
# List open ports
cybersec network ports

# Check specific port
cybersec network check 80

# Complete network analysis
cybersec network analyze
```

### Docker Commands
```bash
# Scan containers
cybersec docker scan

# Detailed report
cybersec docker report

# Check specific container
cybersec docker check <CONTAINER_ID>
```

### Configuration Commands
```bash
# Show configuration
cybersec config show

# Set value
cybersec config set log_level DEBUG

# Reset to default
cybersec config reset
```

### Report Commands
```bash
# Generate report (default: markdown)
cybersec report generate

# Generate report in JSON
cybersec report generate --format json

# Scan history
cybersec report history

# Export last report
cybersec report export /path/to/report.md
```

## Configuration

The toolkit uses a YAML configuration file located at `~/.cybersec/config.yaml` or `/etc/cybersec/config.yaml`. See `config/cybersec.yaml.example` for a complete example.

## Contributing

1. Fork the project
2. Create a feature branch (`git checkout -b feature/new-feature`)
3. Commit your changes (`git commit -m 'Add new feature'`)
4. Push to the branch (`git push origin feature/new-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

Security Team