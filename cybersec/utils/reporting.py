"""Reporting engine module for the cybersecurity toolkit."""
import json
import os
import logging
from datetime import datetime
from typing import Dict, Any, Optional


class ReportingEngine:
    """Reporting engine for generating cybersecurity scan reports."""

    def __init__(self, output_dir: str = 'reports'):
        """
        Initialize the reporting engine.
        
        Args:
            output_dir: Directory to save reports to
        """
        self.output_dir = output_dir
        self.scan_results: Dict[str, Any] = {}
        self.logger = logging.getLogger(__name__)

    def format_report_data(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format scan results for reporting.
        
        Args:
            scan_results: Raw scan results
            
        Returns:
            Formatted scan results
        """
        # Return the results as-is for now, but this could be expanded
        # to normalize data formats, add metadata, etc.
        return scan_results

    def generate_report(self, scan_results: Dict[str, Any], format: str = 'markdown') -> str:
        """
        Generate a report in the specified format.
        
        Args:
            scan_results: Dictionary containing scan results
            format: Output format ('markdown', 'json', 'html', 'txt')
            
        Returns:
            Generated report as a string
        """
        formatted_data = self.format_report_data(scan_results)
        
        if format.lower() == 'json':
            return json.dumps(formatted_data, indent=2, default=str)
        elif format.lower() == 'html':
            return self._generate_html_report(formatted_data)
        elif format.lower() == 'txt':
            return self._generate_txt_report(formatted_data)
        else:  # Default to markdown
            return self._generate_markdown_report(formatted_data)

    def _generate_markdown_report(self, scan_results: Dict[str, Any]) -> str:
        """
        Generate a markdown report.
        
        Args:
            scan_results: Formatted scan results
            
        Returns:
            Markdown report as a string
        """
        report = f"# Cybersecurity Scan Report\n\n"
        report += f"**Generated on:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        # System Information
        if 'system' in scan_results and scan_results['system']:
            report += "## System Information\n\n"
            system_data = scan_results['system']
            if 'hostname' in system_data:
                report += f"- **Hostname:** {system_data['hostname']}\n"
            if 'kernel_version' in system_data:
                report += f"- **Kernel Version:** {system_data['kernel_version']}\n"
            if 'os_version' in system_data:
                report += f"- **OS Version:** {system_data['os_version']}\n"
            if 'users' in system_data:
                report += f"- **Users:** {', '.join(system_data['users'])}\n"
            if 'processes' in system_data:
                report += f"- **Number of Processes:** {len(system_data['processes'])}\n"
            if 'critical_files' in system_data:
                report += f"- **Critical Files:** {len(system_data['critical_files'])}\n"
            report += "\n"
        
        # Network Analysis
        if 'network' in scan_results and scan_results['network']:
            report += "## Network Analysis\n\n"
            network_data = scan_results['network']
            if 'open_ports' in network_data:
                report += f"- **Open Ports:** {', '.join(map(str, network_data['open_ports']))}\n"
            if 'interfaces' in network_data:
                report += f"- **Network Interfaces:** {len(network_data['interfaces'])}\n"
                for interface in network_data['interfaces']:
                    report += f"  - {interface.get('name', 'N/A')}: {interface.get('ip', 'N/A')} ({interface.get('status', 'N/A')})\n"
            report += "\n"
        
        # Firewall Status
        if 'firewall' in scan_results and scan_results['firewall']:
            report += "## Firewall Status\n\n"
            firewall_data = scan_results['firewall']
            if 'ufw_status' in firewall_data:
                report += f"- **UFW Status:** {firewall_data['ufw_status']}\n"
            if 'rules' in firewall_data:
                report += f"- **Firewall Rules:** {len(firewall_data['rules'])}\n"
            if 'banned_ips' in firewall_data:
                report += f"- **Banned IPs:** {', '.join(firewall_data['banned_ips'])}\n"
            report += "\n"
        
        # Docker Security
        if 'docker' in scan_results and scan_results['docker']:
            report += "## Docker Security\n\n"
            docker_data = scan_results['docker']
            if 'containers' in docker_data:
                report += f"- **Containers:** {len(docker_data['containers'])}\n"
            if 'images' in docker_data:
                report += f"- **Images:** {len(docker_data['images'])}\n"
            if 'exposed_ports' in docker_data:
                report += f"- **Exposed Ports:** {', '.join(map(str, docker_data['exposed_ports']))}\n"
            report += "\n"
        
        # Filesystem Security
        if 'filesystem' in scan_results and scan_results['filesystem']:
            report += "## Filesystem Security\n\n"
            filesystem_data = scan_results['filesystem']
            if 'suspicious_files' in filesystem_data:
                report += f"- **Suspicious Files:** {len(filesystem_data['suspicious_files'])}\n"
            if 'world_writable_dirs' in filesystem_data:
                report += f"- **World-Writable Directories:** {len(filesystem_data['world_writable_dirs'])}\n"
            if 'suid_files' in filesystem_data:
                report += f"- **SUID Files:** {len(filesystem_data['suid_files'])}\n"
            if 'recent_files' in filesystem_data:
                report += f"- **Recently Modified Files:** {len(filesystem_data['recent_files'])}\n"
            report += "\n"
        
        # Summary
        report += "## Summary\n\n"
        report += "This report contains the results of a comprehensive cybersecurity scan.\n"
        report += "Please review the findings and take appropriate action to address any security concerns.\n"
        
        return report

    def _generate_html_report(self, scan_results: Dict[str, Any]) -> str:
        """
        Generate an HTML report.
        
        Args:
            scan_results: Formatted scan results
            
        Returns:
            HTML report as a string
        """
        html = "<!DOCTYPE html>\n<html>\n<head>\n"
        html += "<title>Cybersecurity Scan Report</title>\n"
        html += "<style>\n"
        html += "body { font-family: Arial, sans-serif; margin: 20px; }\n"
        html += "h1, h2 { color: #2c3e50; }\n"
        html += "table { border-collapse: collapse; width: 100%; margin: 10px 0; }\n"
        html += "th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n"
        html += "th { background-color: #f2f2f2; }\n"
        html += "</style>\n"
        html += "</head>\n<body>\n"
        
        html += f"<h1>Cybersecurity Scan Report</h1>\n"
        html += f"<p><strong>Generated on:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>\n"
        
        # System Information
        if 'system' in scan_results and scan_results['system']:
            html += "<h2>System Information</h2>\n<ul>\n"
            system_data = scan_results['system']
            if 'hostname' in system_data:
                html += f"<li><strong>Hostname:</strong> {system_data['hostname']}</li>\n"
            if 'kernel_version' in system_data:
                html += f"<li><strong>Kernel Version:</strong> {system_data['kernel_version']}</li>\n"
            if 'os_version' in system_data:
                html += f"<li><strong>OS Version:</strong> {system_data['os_version']}</li>\n"
            if 'users' in system_data:
                html += f"<li><strong>Users:</strong> {', '.join(system_data['users'])}</li>\n"
            html += "</ul>\n"
        
        # Network Analysis
        if 'network' in scan_results and scan_results['network']:
            html += "<h2>Network Analysis</h2>\n<ul>\n"
            network_data = scan_results['network']
            if 'open_ports' in network_data:
                html += f"<li><strong>Open Ports:</strong> {', '.join(map(str, network_data['open_ports']))}</li>\n"
            html += "</ul>\n"
        
        # Add other sections similarly...
        html += "<h2>Report Generated Successfully</h2>\n"
        html += "<p>This report was automatically generated by the Cybersecurity Toolkit.</p>\n"
        
        html += "</body>\n</html>"
        return html

    def _generate_txt_report(self, scan_results: Dict[str, Any]) -> str:
        """
        Generate a plain text report.
        
        Args:
            scan_results: Formatted scan results
            
        Returns:
            Text report as a string
        """
        report = "Cybersecurity Scan Report\n"
        report += "=" * 50 + "\n"
        report += f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        # System Information
        if 'system' in scan_results and scan_results['system']:
            report += "System Information:\n"
            report += "-" * 30 + "\n"
            system_data = scan_results['system']
            if 'hostname' in system_data:
                report += f"Hostname: {system_data['hostname']}\n"
            if 'kernel_version' in system_data:
                report += f"Kernel Version: {system_data['kernel_version']}\n"
            if 'os_version' in system_data:
                report += f"OS Version: {system_data['os_version']}\n"
            report += "\n"
        
        # Add other sections...
        report += "\nReport Generated Successfully\n"
        return report

    def save_report(self, report_content: str, output_file: str):
        """
        Save a report to a file.
        
        Args:
            report_content: Content of the report
            output_file: Path to save the report
        """
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        self.logger.info(f"Report saved to {output_file}")