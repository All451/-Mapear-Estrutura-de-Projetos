"""CLI commands module for the cybersecurity toolkit."""
import click
import logging
from typing import Optional
import datetime

from cybersec.core.scanner import SecurityScanner, ScanType
from cybersec.core.firewall import FirewallScanner
from cybersec.core.network import NetworkScanner
from cybersec.core.docker import DockerScanner
from cybersec.utils.config import ConfigManager
from cybersec.utils.reporting import ReportingEngine


@click.command()
@click.option('--full', 'scan_full', is_flag=True, help='Perform a full security scan')
@click.option('--system', 'scan_system', is_flag=True, help='Scan system information')
@click.option('--network', 'scan_network', is_flag=True, help='Scan network configuration')
@click.option('--firewall', 'scan_firewall', is_flag=True, help='Scan firewall configuration')
@click.option('--docker', 'scan_docker', is_flag=True, help='Scan Docker containers')
@click.option('--filesystem', 'scan_filesystem', is_flag=True, help='Scan filesystem security')
@click.option('--path', default='/tmp', help='Path to scan for filesystem scans')
@click.option('--config', default='config.yaml', help='Configuration file path')
def scan_cmd(scan_full, scan_system, scan_network, scan_firewall, scan_docker, scan_filesystem, path, config):
    """Perform security scans."""
    # Load configuration
    try:
        config_manager = ConfigManager(config)
    except Exception as e:
        click.echo(f"Error loading config: {e}")
        return
    
    # Create scanner
    scanner = SecurityScanner(config_manager)
    
    # Determine which scans to perform
    if scan_full:
        scanner.add_scan_type(ScanType.FULL)
    else:
        if scan_system:
            scanner.add_scan_type(ScanType.SYSTEM)
        if scan_network:
            scanner.add_scan_type(ScanType.NETWORK)
        if scan_firewall:
            scanner.add_scan_type(ScanType.FIREWALL)
        if scan_docker:
            scanner.add_scan_type(ScanType.DOCKER)
        if scan_filesystem:
            scanner.add_scan_type(ScanType.FILESYSTEM)
            # Update config for filesystem path if needed
            config_manager.set('scanner.filesystem_scan_path', path)
    
    # Execute scan
    results = scanner.execute_scan()
    
    # Print results
    click.echo("Scan completed. Results:")
    click.echo(results)


@click.command()
def firewall_status():
    """Show firewall status."""
    firewall_scanner = FirewallScanner()
    status = firewall_scanner.get_ufw_status()
    click.echo(f"Firewall status: {status}")


@click.command()
@click.argument('ip')
@click.option('--reason', help='Reason for the ban')
def ban_cmd(ip, reason):
    """Ban an IP address."""
    firewall_scanner = FirewallScanner()
    success = firewall_scanner.ban_ip(ip, reason)
    if success:
        click.echo(f"Successfully banned IP: {ip}")
    else:
        click.echo(f"Failed to ban IP: {ip}")


@click.command()
@click.argument('ip')
def unban_cmd(ip):
    """Unban an IP address."""
    firewall_scanner = FirewallScanner()
    success = firewall_scanner.unban_ip(ip)
    if success:
        click.echo(f"Successfully unbanned IP: {ip}")
    else:
        click.echo(f"Failed to unban IP: {ip}")


@click.command()
def list_banned():
    """List banned IP addresses."""
    firewall_scanner = FirewallScanner()
    banned_ips = firewall_scanner.list_banned_ips()
    if banned_ips:
        click.echo("Banned IP addresses:")
        for ip in banned_ips:
            click.echo(f"  - {ip}")
    else:
        click.echo("No banned IP addresses.")


@click.command()
@click.argument('ip')
def check_cmd(ip):
    """Check if an IP is banned."""
    firewall_scanner = FirewallScanner()
    status = firewall_scanner.check_ip_status(ip)
    click.echo(f"IP {ip} status: {status}")


@click.command()
def ports_cmd():
    """Show open ports."""
    network_scanner = NetworkScanner()
    open_ports = network_scanner.get_open_ports()
    click.echo(f"Open ports: {open_ports}")


@click.command()
@click.argument('port', type=int)
@click.option('--host', default='127.0.0.1', help='Host to check (default: 127.0.0.1)')
def check_port_cmd(host, port):
    """Check if a port is open."""
    network_scanner = NetworkScanner()
    is_open = network_scanner.check_port(host, port)
    status = "open" if is_open else "closed"
    click.echo(f"Port {port} on {host} is {status}")


@click.command()
def docker_scan_cmd():
    """Scan Docker containers and images."""
    docker_scanner = DockerScanner()
    results = docker_scanner.scan()
    
    click.echo("Docker scan results:")
    click.echo(f"Containers: {len(results.get('containers', []))}")
    click.echo(f"Images: {len(results.get('images', []))}")
    click.echo(f"Exposed ports: {results.get('exposed_ports', [])}")


@click.command()
def docker_report_cmd():
    """Generate Docker security report."""
    docker_scanner = DockerScanner()
    results = docker_scanner.scan()
    
    reporter = ReportingEngine()
    report_content = reporter.generate_report({'docker': results}, format='markdown')
    
    # Save report
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"docker_report_{timestamp}.md"
    reporter.save_report(report_content, output_file)
    click.echo(f"Docker report saved to {output_file}")


@click.command()
def config_show():
    """Show current configuration."""
    # This would typically load and display the config
    click.echo("Configuration display not yet implemented.")


@click.command()
@click.option('--format', 'report_format', default='markdown', 
              type=click.Choice(['markdown', 'json', 'html', 'txt']),
              help='Report format')
@click.option('--output', default='security_report.md', help='Output file path')
def report_generate(report_format, output):
    """Generate a security report."""
    # This would typically use previously saved scan results
    # For now, we'll create a sample report
    reporter = ReportingEngine()
    sample_results = {
        'system': {'hostname': 'sample-host', 'os': 'Linux'},
        'network': {'open_ports': [22, 80, 443]}
    }
    
    report_content = reporter.generate_report(sample_results, format=report_format)
    reporter.save_report(report_content, output)
    click.echo(f"Report generated and saved to {output}")