"""Command implementations for the Cybersecurity Toolkit CLI."""
import sys
import os
from typing import Dict, Any, List
import logging
import json
from datetime import datetime

from cybersec.core.scanner import get_scanner
from cybersec.core.firewall import FirewallManager
from cybersec.core.network import NetworkScanner
from cybersec.core.docker import DockerScanner
from cybersec.core.filesystem import FilesystemScanner
from cybersec.utils.config import get_config
from cybersec.utils.reporting import ReportGenerator, ReportHistory
from cybersec.utils.logger import setup_logging
from cybersec.__version__ import __version__


class CommandHandler:
    """Handles execution of CLI commands."""
    
    def __init__(self):
        """Initialize command handler."""
        self.config = get_config()
        self.scanner = get_scanner()
        self.firewall_manager = FirewallManager()
        self.network_scanner = NetworkScanner()
        self.docker_scanner = DockerScanner()
        self.filesystem_scanner = FilesystemScanner()
        self.report_generator = ReportGenerator()
        self.report_history = ReportHistory()
        
        # Setup logging based on config
        log_level = self.config.get("log_level", "INFO")
        self.logger = setup_logging(log_level)
    
    def handle_scan(self, args) -> int:
        """Handle scan commands.
        
        Args:
            args: Parsed arguments
            
        Returns:
            Exit code
        """
        try:
            if args.scan_type == 'full':
                results = self.scanner.full_scan()
            elif args.scan_type == 'quick':
                results = self.scanner.quick_scan()
            elif args.scan_type == 'system':
                results = {'system': self.scanner.scan_system()}
            elif args.scan_type == 'network':
                results = {'network': self.scanner.scan_network()}
            elif args.scan_type == 'docker':
                results = {'docker': self.scanner.scan_docker()}
            elif args.scan_type == 'filesystem':
                results = {'filesystem': self.scanner.scan_filesystem(args.path)}
            else:
                print("Error: Please specify a scan type (full, quick, system, network, docker, filesystem)")
                return 1
            
            # Generate report
            summary = self.scanner.get_summary()
            
            # Prepare report data
            report_data = {
                'timestamp': datetime.now().isoformat(),
                'version': __version__,
                'scan_type': args.scan_type or 'custom',
                'duration': 0,  # Would need to track this properly
                'summary': summary,
                'findings': results,
                'system_info': self._get_system_info(),
                'recommendations': self._generate_recommendations(results, summary)
            }
            
            # Generate report in specified format
            report_path = self.report_generator.generate_report(
                report_data, 
                format_type=args.format
            )
            
            print(f"Scan completed! Report generated: {report_path}")
            print(f"Findings summary: {summary}")
            
            return 0
        
        except Exception as e:
            self.logger.error(f"Error during scan: {e}")
            print(f"Error during scan: {e}")
            return 1
    
    def handle_firewall(self, args) -> int:
        """Handle firewall commands.
        
        Args:
            args: Parsed arguments
            
        Returns:
            Exit code
        """
        try:
            if args.firewall_action == 'status':
                status = self.firewall_manager.get_firewall_status()
                print(f"Firewall Status:")
                print(f"  UFW Active: {status['ufw_active']}")
                print(f"  iptables Active: {status['iptables_active']}")
                print(f"  firewalld Active: {status['firewalld_active']}")
                print(f"  Rules Count: {status['rules_count']}")
                
            elif args.firewall_action == 'ban':
                success = self.firewall_manager.ban_ip(
                    args.ip, 
                    reason=args.reason, 
                    duration=args.duration
                )
                if success:
                    print(f"Successfully banned IP: {args.ip}")
                else:
                    print(f"Failed to ban IP: {args.ip}")
                    return 1
                    
            elif args.firewall_action == 'unban':
                success = self.firewall_manager.unban_ip(args.ip)
                if success:
                    print(f"Successfully unbanned IP: {args.ip}")
                else:
                    print(f"Failed to unban IP: {args.ip}")
                    return 1
                    
            elif args.firewall_action == 'list':
                banned_ips = self.firewall_manager.list_banned_ips()
                if banned_ips:
                    print("Banned IPs:")
                    for entry in banned_ips:
                        print(f"  {entry['ip']} ({entry['method']}): {entry['rule']}")
                else:
                    print("No banned IPs found.")
                    
            elif args.firewall_action == 'check':
                status = self.firewall_manager.check_ip_status(args.ip)
                if status['banned']:
                    print(f"IP {args.ip} is banned (method: {status['method']})")
                else:
                    print(f"IP {args.ip} is not banned")
            else:
                print("Error: Please specify a firewall action (status, ban, unban, list, check)")
                return 1
            
            return 0
        
        except Exception as e:
            self.logger.error(f"Error in firewall command: {e}")
            print(f"Error in firewall command: {e}")
            return 1
    
    def handle_network(self, args) -> int:
        """Handle network commands.
        
        Args:
            args: Parsed arguments
            
        Returns:
            Exit code
        """
        try:
            if args.network_action == 'ports':
                # Get open ports using the network scanner
                open_ports = self.network_scanner._get_open_ports()
                if open_ports:
                    print("Open ports:")
                    for port, protocol, process in open_ports:
                        print(f"  {port}/{protocol} - {process}")
                else:
                    print("No open ports found or unable to retrieve port information.")
                    
            elif args.network_action == 'check':
                # Check if specific port is open on localhost
                is_open = self.network_scanner.scan_port('127.0.0.1', args.port)
                if is_open:
                    print(f"Port {args.port} is open on localhost")
                else:
                    print(f"Port {args.port} is closed on localhost")
                    
            elif args.network_action == 'analyze':
                # Perform network scan
                results = self.scanner.scan_network()
                summary = {
                    'critical': sum(1 for f in results if f.get('severity') == 'critical'),
                    'high': sum(1 for f in results if f.get('severity') == 'high'),
                    'medium': sum(1 for f in results if f.get('severity') == 'medium'),
                    'low': sum(1 for f in results if f.get('severity') == 'low'),
                    'total': len(results)
                }
                
                print(f"Network analysis completed with {len(results)} findings:")
                print(f"  Critical: {summary['critical']}")
                print(f"  High: {summary['high']}")
                print(f"  Medium: {summary['medium']}")
                print(f"  Low: {summary['low']}")
                
                if results:
                    print("\nDetailed findings:")
                    for finding in results:
                        print(f"  - {finding['title']} [{finding['severity'].upper()}]: {finding['description']}")
            else:
                print("Error: Please specify a network action (ports, check, analyze)")
                return 1
            
            return 0
        
        except Exception as e:
            self.logger.error(f"Error in network command: {e}")
            print(f"Error in network command: {e}")
            return 1
    
    def handle_docker(self, args) -> int:
        """Handle Docker commands.
        
        Args:
            args: Parsed arguments
            
        Returns:
            Exit code
        """
        try:
            if not self.docker_scanner.is_docker_available():
                print("Docker is not available or accessible")
                return 1
            
            if args.docker_action == 'scan':
                results = self.scanner.scan_docker()
                summary = {
                    'critical': sum(1 for f in results if f.get('severity') == 'critical'),
                    'high': sum(1 for f in results if f.get('severity') == 'high'),
                    'medium': sum(1 for f in results if f.get('severity') == 'medium'),
                    'low': sum(1 for f in results if f.get('severity') == 'low'),
                    'total': len(results)
                }
                
                print(f"Docker scan completed with {len(results)} findings:")
                print(f"  Critical: {summary['critical']}")
                print(f"  High: {summary['high']}")
                print(f"  Medium: {summary['medium']}")
                print(f"  Low: {summary['low']}")
                
                if results:
                    print("\nDetailed findings:")
                    for finding in results:
                        print(f"  - {finding['title']} [{finding['severity'].upper()}]: {finding['description']}")
                        
            elif args.docker_action == 'report':
                # Get Docker security information
                info = self.docker_scanner.get_docker_security_info()
                print("Docker Security Report:")
                print(f"  Available: {info['available']}")
                if info['available']:
                    print(f"  Version: {info.get('version', 'unknown')}")
                    print(f"  Running Containers: {info['containers_running']}")
                    print(f"  Total Images: {info['images_count']}")
                    print(f"  Security Features:")
                    for feature, enabled in info['security_features'].items():
                        print(f"    {feature}: {enabled}")
                        
            elif args.docker_action == 'check':
                results = self.docker_scanner.scan_container(args.container)
                print(f"Container {args.container} security check:")
                if results:
                    for finding in results:
                        print(f"  - {finding['title']} [{finding['severity'].upper()}]: {finding['description']}")
                else:
                    print("  No security issues found")
            else:
                print("Error: Please specify a Docker action (scan, report, check)")
                return 1
            
            return 0
        
        except Exception as e:
            self.logger.error(f"Error in Docker command: {e}")
            print(f"Error in Docker command: {e}")
            return 1
    
    def handle_config(self, args) -> int:
        """Handle configuration commands.
        
        Args:
            args: Parsed arguments
            
        Returns:
            Exit code
        """
        try:
            if args.config_action == 'show':
                config_data = self.config.get_all()
                print("Current Configuration:")
                print(json.dumps(config_data, indent=2, default=str))
                
            elif args.config_action == 'set':
                self.config.set(args.key, args.value)
                print(f"Configuration {args.key} set to {args.value}")
                
            elif args.config_action == 'reset':
                self.config.reset_to_defaults()
                print("Configuration reset to defaults")
            else:
                print("Error: Please specify a config action (show, set, reset)")
                return 1
            
            return 0
        
        except Exception as e:
            self.logger.error(f"Error in config command: {e}")
            print(f"Error in config command: {e}")
            return 1
    
    def handle_report(self, args) -> int:
        """Handle report commands.
        
        Args:
            args: Parsed arguments
            
        Returns:
            Exit code
        """
        try:
            if args.report_action == 'generate':
                # Use the last scan results if available, otherwise do a quick scan
                if not any(self.scanner.scan_results.values()):
                    print("No previous scan results. Performing quick scan...")
                    self.scanner.quick_scan()
                
                summary = self.scanner.get_summary()
                
                # Prepare report data
                report_data = {
                    'timestamp': datetime.now().isoformat(),
                    'version': __version__,
                    'scan_type': 'manual',
                    'duration': 0,  # Would need to track this properly
                    'summary': summary,
                    'findings': self.scanner.scan_results,
                    'system_info': self._get_system_info(),
                    'recommendations': self._generate_recommendations(
                        self.scanner.scan_results, summary
                    )
                }
                
                # Generate report
                report_path = self.report_generator.generate_report(
                    report_data, 
                    format_type=args.format,
                    filename=args.output
                )
                
                print(f"Report generated: {report_path}")
                
            elif args.report_action == 'history':
                reports = self.report_history.get_recent_reports()
                if reports:
                    print("Recent Reports:")
                    for report in reports:
                        print(f"  {report['name']} ({report['size']} bytes) - {report['modified']}")
                else:
                    print("No reports found")
                    
            elif args.report_action == 'export':
                # This would export the last generated report
                # For now, we'll just indicate it's not implemented
                print(f"Export functionality would save to: {args.file}")
                print("Note: Export functionality requires storing the last report path")
            else:
                print("Error: Please specify a report action (generate, history, export)")
                return 1
            
            return 0
        
        except Exception as e:
            self.logger.error(f"Error in report command: {e}")
            print(f"Error in report command: {e}")
            return 1
    
    def _get_system_info(self) -> Dict[str, str]:
        """Get basic system information.
        
        Returns:
            Dictionary with system information
        """
        import platform
        import socket
        import psutil
        
        try:
            return {
                'hostname': socket.gethostname(),
                'os': f"{platform.system()} {platform.release()}",
                'kernel': platform.release(),
                'uptime': str(datetime.now() - datetime.fromtimestamp(psutil.boot_time())),
                'load_avg': str(os.getloadavg() if hasattr(os, 'getloadavg') else 'N/A')
            }
        except Exception:
            return {
                'hostname': 'Unknown',
                'os': 'Unknown',
                'kernel': 'Unknown',
                'uptime': 'Unknown',
                'load_avg': 'Unknown'
            }
    
    def _generate_recommendations(self, findings: Dict[str, List[Dict]], summary: Dict[str, int]) -> List[str]:
        """Generate security recommendations based on findings.
        
        Args:
            findings: Dictionary of scan findings
            summary: Summary of findings by severity
            
        Returns:
            List of recommendations
        """
        recommendations = []
        
        # Add recommendations based on summary
        if summary.get('critical', 0) > 0:
            recommendations.append("Address critical issues immediately")
        
        if summary.get('high', 0) > 0:
            recommendations.append("Prioritize fixing high severity issues")
        
        if summary.get('medium', 0) > 0:
            recommendations.append("Review and address medium severity issues")
        
        # Add specific recommendations based on finding types
        for scan_type, scan_findings in findings.items():
            for finding in scan_findings:
                title = finding.get('title', '').lower()
                if 'unauthorized' in title or 'access' in title:
                    recommendations.append("Review access controls and permissions")
                elif 'firewall' in title:
                    recommendations.append("Ensure firewall rules are properly configured")
                elif 'exposed' in title:
                    recommendations.append("Limit network exposure of services")
                elif 'root' in title:
                    recommendations.append("Avoid running processes as root when possible")
        
        # Remove duplicates while preserving order
        unique_recommendations = []
        for rec in recommendations:
            if rec not in unique_recommendations:
                unique_recommendations.append(rec)
        
        # If no specific recommendations, add general ones
        if not unique_recommendations:
            unique_recommendations = [
                "Keep system and software up to date",
                "Review and harden system configuration",
                "Monitor system logs regularly",
                "Implement defense in depth security measures"
            ]
        
        return unique_recommendations