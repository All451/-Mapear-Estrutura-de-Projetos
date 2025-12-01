# Quick Start Guide

## Installation

### Prerequisites
- Python 3.8+
- Linux (Ubuntu 20.04+, Debian 11+, CentOS 8+)
- UFW (Uncomplicated Firewall) installed
- Docker (optional, for container scanning)

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Install the Toolkit
```bash
python setup.py install
```

## Basic Usage

### Check Version
```bash
cybersec --version
```

### Get Help
```bash
cybersec --help
```

### Perform a Full Security Scan
```bash
cybersec scan full
```

### Perform a Quick Security Scan
```bash
cybersec scan quick
```

### Check Firewall Status
```bash
cybersec firewall status
```

### Ban an IP Address
```bash
cybersec firewall ban 192.168.1.100 --reason "Suspicious activity"
```

### List Open Network Ports
```bash
cybersec network ports
```

### Scan Docker Containers
```bash
cybersec docker scan
```

## Configuration

The toolkit uses a YAML configuration file. By default, it looks for configuration in:
1. `~/.cybersec/config.yaml`
2. `/etc/cybersec/config.yaml`
3. `config/cybersec.yaml.example` (as fallback)

To create a custom configuration:
```bash
mkdir -p ~/.cybersec
cp config/cybersec.yaml.example ~/.cybersec/config.yaml
```

## Common Commands

### System Scanning
```bash
# Scan system only
cybersec scan system

# Scan filesystem
cybersec scan filesystem /path/to/directory
```

### Network Analysis
```bash
# Check specific port
cybersec network check 80

# Complete network analysis
cybersec network analyze
```

### Docker Security
```bash
# Check specific container
cybersec docker check <container_id>

# Generate Docker report
cybersec docker report
```

### Reports
```bash
# Generate report in different formats
cybersec report generate --format json
cybersec report generate --format html
cybersec report generate --format txt

# View report history
cybersec report history
```

## Examples

### Full Security Assessment
```bash
# Perform comprehensive scan and generate HTML report
cybersec scan full --format html
```

### Firewall Management
```bash
# List banned IPs
cybersec firewall list

# Check if IP is banned
cybersec firewall check 192.168.1.100

# Unban IP
cybersec firewall unban 192.168.1.100
```

### Configuration Management
```bash
# Show current configuration
cybersec config show

# Set specific configuration value
cybersec config set log_level DEBUG

# Reset to default configuration
cybersec config reset
```

## Troubleshooting

### Permission Issues
Many security operations require elevated privileges. Run with sudo when needed:
```bash
sudo cybersec scan full
```

### Docker Not Available
If Docker is not installed or accessible:
- The toolkit will skip Docker-related scans
- Docker commands will show an appropriate error message
- All other functionality remains available

### Missing Dependencies
If you encounter import errors, ensure all dependencies are installed:
```bash
pip install -r requirements.txt
```