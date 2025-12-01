"""Command line interface parser for the Cybersecurity Toolkit."""
import argparse
import sys
from typing import Any, Dict

from cybersec.__version__ import __version__


def create_parser() -> argparse.ArgumentParser:
    """Create the main argument parser.
    
    Returns:
        Configured argument parser
    """
    parser = argparse.ArgumentParser(
        prog='cybersec',
        description='Cybersecurity Toolkit - Comprehensive security scanning and management',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  cybersec --version                           # Show version
  cybersec scan --full                         # Full security scan
  cybersec scan --system                       # System-only scan
  cybersec firewall status                     # Show firewall status
  cybersec firewall ban 192.168.1.100          # Ban IP address
  cybersec network ports                       # List open ports
  cybersec docker scan                         # Scan Docker containers
  cybersec report generate --format html       # Generate HTML report
        """
    )
    
    parser.add_argument(
        '--version', 
        action='version', 
        version=f'Cybersecurity Toolkit v{__version__}'
    )
    
    # Create subparsers for different command groups
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan commands
    scan_parser = subparsers.add_parser('scan', help='Security scanning commands')
    scan_subparsers = scan_parser.add_subparsers(dest='scan_type', help='Scan types')
    
    # Full scan
    scan_subparsers.add_parser('full', help='Perform full security scan').add_argument(
        '--format', '-f', choices=['markdown', 'json', 'html', 'txt'], 
        default='markdown', help='Output format for scan results'
    )
    
    # Quick scan
    scan_subparsers.add_parser('quick', help='Perform quick security scan').add_argument(
        '--format', '-f', choices=['markdown', 'json', 'html', 'txt'], 
        default='markdown', help='Output format for scan results'
    )
    
    # System scan
    scan_subparsers.add_parser('system', help='Perform system security scan').add_argument(
        '--format', '-f', choices=['markdown', 'json', 'html', 'txt'], 
        default='markdown', help='Output format for scan results'
    )
    
    # Network scan
    scan_subparsers.add_parser('network', help='Perform network security scan').add_argument(
        '--format', '-f', choices=['markdown', 'json', 'html', 'txt'], 
        default='markdown', help='Output format for scan results'
    )
    
    # Docker scan
    scan_subparsers.add_parser('docker', help='Perform Docker security scan').add_argument(
        '--format', '-f', choices=['markdown', 'json', 'html', 'txt'], 
        default='markdown', help='Output format for scan results'
    )
    
    # Filesystem scan
    filesystem_scan = scan_subparsers.add_parser('filesystem', help='Perform filesystem security scan')
    filesystem_scan.add_argument('path', nargs='?', default='/', help='Path to scan (default: /)')
    filesystem_scan.add_argument(
        '--format', '-f', choices=['markdown', 'json', 'html', 'txt'], 
        default='markdown', help='Output format for scan results'
    )
    
    # Firewall commands
    firewall_parser = subparsers.add_parser('firewall', help='Firewall management commands')
    firewall_subparsers = firewall_parser.add_subparsers(dest='firewall_action', help='Firewall actions')
    
    # Firewall status
    firewall_subparsers.add_parser('status', help='Show firewall status')
    
    # Firewall ban
    ban_parser = firewall_subparsers.add_parser('ban', help='Ban IP address')
    ban_parser.add_argument('ip', help='IP address to ban')
    ban_parser.add_argument('--reason', '-r', help='Reason for the ban')
    ban_parser.add_argument('--duration', '-d', type=int, help='Ban duration in seconds (default: config value)')
    
    # Firewall unban
    unban_parser = firewall_subparsers.add_parser('unban', help='Unban IP address')
    unban_parser.add_argument('ip', help='IP address to unban')
    
    # Firewall list
    firewall_subparsers.add_parser('list', help='List banned IP addresses')
    
    # Firewall check
    check_parser = firewall_subparsers.add_parser('check', help='Check if IP is banned')
    check_parser.add_argument('ip', help='IP address to check')
    
    # Network commands
    network_parser = subparsers.add_parser('network', help='Network analysis commands')
    network_subparsers = network_parser.add_subparsers(dest='network_action', help='Network actions')
    
    # Network ports
    network_subparsers.add_parser('ports', help='List open network ports')
    
    # Network check
    check_port_parser = network_subparsers.add_parser('check', help='Check specific port')
    check_port_parser.add_argument('port', type=int, help='Port number to check')
    
    # Network analyze
    network_subparsers.add_parser('analyze', help='Perform complete network analysis')
    
    # Docker commands
    docker_parser = subparsers.add_parser('docker', help='Docker security commands')
    docker_subparsers = docker_parser.add_subparsers(dest='docker_action', help='Docker actions')
    
    # Docker scan
    docker_subparsers.add_parser('scan', help='Scan Docker containers and images')
    
    # Docker report
    docker_subparsers.add_parser('report', help='Generate Docker security report')
    
    # Docker check
    docker_check_parser = docker_subparsers.add_parser('check', help='Check specific container')
    docker_check_parser.add_argument('container', help='Container ID or name to check')
    
    # Config commands
    config_parser = subparsers.add_parser('config', help='Configuration management commands')
    config_subparsers = config_parser.add_subparsers(dest='config_action', help='Configuration actions')
    
    # Config show
    config_subparsers.add_parser('show', help='Show current configuration')
    
    # Config set
    set_parser = config_subparsers.add_parser('set', help='Set configuration value')
    set_parser.add_argument('key', help='Configuration key')
    set_parser.add_argument('value', help='Configuration value')
    
    # Config reset
    config_subparsers.add_parser('reset', help='Reset to default configuration')
    
    # Report commands
    report_parser = subparsers.add_parser('report', help='Report generation commands')
    report_subparsers = report_parser.add_subparsers(dest='report_action', help='Report actions')
    
    # Report generate
    generate_parser = report_subparsers.add_parser('generate', help='Generate security report')
    generate_parser.add_argument(
        '--format', '-f', choices=['markdown', 'json', 'html', 'txt'], 
        default='markdown', help='Output format for report'
    )
    generate_parser.add_argument(
        '--output', '-o', help='Output file path (default: auto-generated)'
    )
    
    # Report history
    report_subparsers.add_parser('history', help='Show report history')
    
    # Report export
    export_parser = report_subparsers.add_parser('export', help='Export last report')
    export_parser.add_argument('file', help='Output file path')
    
    return parser


def parse_args(args: list = None) -> argparse.Namespace:
    """Parse command line arguments.
    
    Args:
        args: List of arguments to parse (default: sys.argv[1:])
        
    Returns:
        Parsed arguments namespace
    """
    parser = create_parser()
    
    # If no arguments provided, show help
    if args is None:
        args = sys.argv[1:]
        if not args:
            parser.print_help()
            sys.exit(0)
    
    parsed_args = parser.parse_args(args)
    
    # Validate arguments
    validate_args(parsed_args, parser)
    
    return parsed_args


def validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Validate parsed arguments.
    
    Args:
        args: Parsed arguments namespace
        parser: Argument parser for error reporting
    """
    # Validate IP addresses where needed
    if hasattr(args, 'ip') and args.ip:
        _validate_ip(args.ip, parser)
    
    # Validate port numbers where needed
    if hasattr(args, 'port') and args.port:
        if not (1 <= args.port <= 65535):
            parser.error(f"Port must be between 1 and 65535, got {args.port}")


def _validate_ip(ip: str, parser: argparse.ArgumentParser) -> None:
    """Validate IP address format.
    
    Args:
        ip: IP address to validate
        parser: Argument parser for error reporting
    """
    import ipaddress
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        parser.error(f"Invalid IP address: {ip}")