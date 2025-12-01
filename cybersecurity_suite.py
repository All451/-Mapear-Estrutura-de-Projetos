#!/usr/bin/env python3
"""
Cybersecurity Suite - A Comprehensive Cybersecurity Tool
This tool integrates multiple security modules for comprehensive system analysis and protection.
"""
import os
import sys
import subprocess
import argparse
import json
import socket
import requests
from datetime import datetime
import hashlib
import threading
import time
from cybersecurity_module import *
from ufw_port_checker import *
from fban2 import FBan2
from docker_exposure_checker import DockerExposureChecker

class CybersecuritySuite:
    """
    A comprehensive cybersecurity suite that integrates multiple security tools
    """
    def __init__(self):
        self.fban = FBan2()
        self.docker_checker = DockerExposureChecker()
        self.scan_results = {}
    
    def run_comprehensive_scan(self):
        """
        Run a comprehensive security scan using all available tools
        """
        print("="*60)
        print("CYBERSECURITY COMPREHENSIVE SCAN")
        print("="*60)
        
        # 1. System integrity check
        print("\n[1/6] Running System Integrity Check...")
        self.system_integrity_scan()
        
        # 2. Network security check
        print("\n[2/6] Running Network Security Check...")
        self.network_security_scan()
        
        # 3. Firewall analysis
        print("\n[3/6] Running Firewall Analysis...")
        self.firewall_analysis()
        
        # 4. Docker container exposure check
        print("\n[4/6] Running Docker Container Exposure Check...")
        self.docker_exposure_scan()
        
        # 5. File system security check
        print("\n[5/6] Running File System Security Check...")
        self.file_system_security_scan()
        
        # 6. Active ban status
        print("\n[6/6] Checking Active Firewall Bans...")
        self.ban_status_check()
        
        # Generate final report
        self.generate_comprehensive_report()
    
    def system_integrity_scan(self):
        """
        Perform system integrity checks
        """
        print("  - Checking system for common security issues...")
        security_audit()
        
        print("  - Checking system integrity...")
        check_system_integrity()
        
        # Additional checks
        self.check_running_processes()
        self.check_system_logs()
    
    def check_running_processes(self):
        """
        Check for suspicious running processes
        """
        try:
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
            processes = result.stdout.split('\n')
            
            suspicious_processes = []
            for process in processes[1:]:  # Skip header
                if process:
                    # Look for common suspicious processes
                    if any(suspicious in process for suspicious in ['minerd', 'xmr', 'crypto', 'stratum']):
                        suspicious_processes.append(process)
            
            if suspicious_processes:
                print(f"  - Found {len(suspicious_processes)} potentially suspicious processes")
                for proc in suspicious_processes:
                    print(f"    {proc[:100]}...")
            else:
                print("  - No suspicious processes detected")
        except Exception as e:
            print(f"  - Error checking processes: {e}")
    
    def check_system_logs(self):
        """
        Check system logs for security events
        """
        log_files = [
            '/var/log/auth.log',
            '/var/log/secure',  # RHEL/CentOS
            '/var/log/syslog',
            '/var/log/messages'
        ]
        
        suspicious_logins = []
        for log_file in log_files:
            if os.path.exists(log_file):
                try:
                    with open(log_file, 'r') as f:
                        lines = f.readlines()[-50:]  # Check last 50 lines
                        
                        for line in lines:
                            if any(keyword in line.lower() for keyword in ['failed', 'invalid', 'authentication failure']):
                                suspicious_logins.append(line.strip())
                except:
                    continue
        
        if suspicious_logins:
            print(f"  - Found {len(suspicious_logins)} suspicious authentication events in logs")
        else:
            print("  - No suspicious authentication events found in recent logs")
    
    def network_security_scan(self):
        """
        Perform network security checks
        """
        # Check open ports
        ports = list_open_ports()
        if isinstance(ports, list):
            print(f"  - Found {len(ports)} open ports via UFW")
            for port in ports:
                print(f"    Port {port['port']} ({port['protocol']}) - {port['status']}")
        else:
            print(f"  - UFW status: {ports}")
        
        # Check for common vulnerable ports
        vulnerable_ports = ['21', '23', '135', '139', '445', '3389']
        open_vulnerable = []
        if isinstance(ports, list):
            for port in ports:
                port_num = port['port'].split(':')[0]  # Handle port ranges like 8000:9000
                if port_num in vulnerable_ports:
                    open_vulnerable.append(f"{port_num}/{port['protocol']}")
        
        if open_vulnerable:
            print(f"  - WARNING: {len(open_vulnerable)} potentially vulnerable ports are open: {', '.join(open_vulnerable)}")
        else:
            print("  - No commonly vulnerable ports detected")
    
    def firewall_analysis(self):
        """
        Analyze firewall configuration
        """
        ufw_status = check_ufw_status()
        print("  - UFW Status:")
        for line in ufw_status.split('\n'):
            print(f"    {line}")
    
    def docker_exposure_scan(self):
        """
        Scan for Docker container exposures
        """
        try:
            report = self.docker_checker.generate_report()
            print("  - Docker exposure report:")
            for line in report.split('\n'):
                print(f"    {line}")
        except Exception as e:
            print(f"  - Error checking Docker exposure: {e}")
            print("    (Docker may not be installed or accessible)")
    
    def file_system_security_scan(self):
        """
        Scan file system for security issues
        """
        print("  - Scanning for sensitive files...")
        
        # Check common sensitive locations
        sensitive_paths = [
            '/etc/passwd',
            '/etc/shadow', 
            '/etc/hosts',
            '/etc/network/',
            '/home/',
            '/root/',
            '/tmp/',
            '/var/log/',
            '/etc/ssh/'
        ]
        
        # Look for sensitive files in current directory
        sensitive_files = []
        for root, dirs, files in os.walk('.'):
            for file in files:
                if any(sensitive in file.lower() for sensitive in 
                      ['.env', 'config', 'password', 'secret', 'key', 'token', '.pem', '.key', 'id_rsa']):
                    sensitive_files.append(os.path.join(root, file))
        
        if sensitive_files:
            print(f"  - Found {len(sensitive_files)} potentially sensitive files:")
            for file in sensitive_files[:10]:  # Limit output
                print(f"    {file}")
            if len(sensitive_files) > 10:
                print(f"    ... and {len(sensitive_files) - 10} more")
        else:
            print("  - No sensitive files detected in current directory")
    
    def ban_status_check(self):
        """
        Check active firewall bans
        """
        banned_ips = self.fban.list_banned_ips()
        print(f"  - Total banned IPs: {len(banned_ips)}")
        if banned_ips:
            for ip in banned_ips[:10]:  # Limit output
                print(f"    {ip}")
            if len(banned_ips) > 10:
                print(f"    ... and {len(banned_ips) - 10} more")
    
    def generate_comprehensive_report(self):
        """
        Generate a comprehensive security report
        """
        print("\n" + "="*60)
        print("COMPREHENSIVE SECURITY REPORT")
        print("="*60)
        
        # Summary of findings
        print("\nSUMMARY:")
        print("  - System integrity: CHECKED")
        print("  - Network security: CHECKED") 
        print("  - Firewall status: CHECKED")
        print("  - Docker exposure: CHECKED")
        print("  - File system security: CHECKED")
        print("  - Active bans: CHECKED")
        
        print("\nRECOMMENDATIONS:")
        print("  - Review all open ports and close unnecessary ones")
        print("  - Regularly update system packages")
        print("  - Monitor system logs for suspicious activity")
        print("  - Implement strong password policies")
        print("  - Use fail2ban or similar tools for automatic blocking")
        print("  - Regular security audits")
    
    def interactive_mode(self):
        """
        Run the suite in interactive mode
        """
        while True:
            print("\n" + "="*50)
            print("CYBERSECURITY SUITE - INTERACTIVE MODE")
            print("="*50)
            print("1. Run Comprehensive Security Scan")
            print("2. Network Security Analysis")
            print("3. Firewall Management")
            print("4. Docker Container Security")
            print("5. File System Security")
            print("6. Threat Intelligence Check")
            print("7. Exit")
            
            choice = input("\nSelect an option (1-7): ").strip()
            
            if choice == '1':
                self.run_comprehensive_scan()
            elif choice == '2':
                self.network_security_menu()
            elif choice == '3':
                self.firewall_management_menu()
            elif choice == '4':
                self.docker_security_menu()
            elif choice == '5':
                self.file_system_security_menu()
            elif choice == '6':
                self.threat_intelligence_check()
            elif choice == '7':
                print("Exiting Cybersecurity Suite. Stay secure!")
                break
            else:
                print("Invalid option. Please select 1-7.")
    
    def network_security_menu(self):
        """
        Network security submenu
        """
        print("\n--- NETWORK SECURITY ANALYSIS ---")
        print("Current UFW Status:")
        print(check_ufw_status())
        
        print("\nOpen ports:")
        ports = list_open_ports()
        if isinstance(ports, list):
            for port in ports:
                print(f"  Port: {port['port']}, Protocol: {port['protocol']}, Status: {port['status']}")
        else:
            print(ports)
    
    def firewall_management_menu(self):
        """
        Firewall management submenu
        """
        print("\n--- FIREWALL MANAGEMENT ---")
        while True:
            print("\nFirewall Management Options:")
            print("  1. Ban an IP address")
            print("  2. Unban an IP address")
            print("  3. Check IP status")
            print("  4. List banned IPs")
            print("  5. Back to main menu")
            
            choice = input("Select an option (1-5): ").strip()
            
            if choice == '1':
                ip = input("Enter IP address to ban: ").strip()
                reason = input("Enter reason for ban (optional): ").strip() or "Manual ban"
                self.fban.ban_ip(ip, reason)
            elif choice == '2':
                ip = input("Enter IP address to unban: ").strip()
                self.fban.unban_ip(ip)
            elif choice == '3':
                ip = input("Enter IP address to check: ").strip()
                status = self.fban.check_ip_status(ip)
                print(f"IP {ip} is {'banned' if status else 'not banned'}")
            elif choice == '4':
                banned_ips = self.fban.list_banned_ips()
                print("Banned IPs:")
                if banned_ips:
                    for ip in banned_ips:
                        print(f"  {ip}")
                else:
                    print("  No IPs are currently banned")
            elif choice == '5':
                break
            else:
                print("Invalid option. Please select 1-5.")
    
    def docker_security_menu(self):
        """
        Docker security submenu
        """
        print("\n--- DOCKER CONTAINER SECURITY ---")
        try:
            print(self.docker_checker.generate_report())
            print("\n" + "\n".join(self.docker_checker.get_security_recommendations()))
        except Exception as e:
            print(f"Error checking Docker security: {e}")
            print("Make sure Docker is installed and running.")
    
    def file_system_security_menu(self):
        """
        File system security submenu
        """
        print("\n--- FILE SYSTEM SECURITY ---")
        print("Checking for sensitive files in current directory...")
        
        # Look for sensitive files
        sensitive_files = []
        for root, dirs, files in os.walk('.'):
            for file in files:
                if any(sensitive in file.lower() for sensitive in 
                      ['.env', 'config', 'password', 'secret', 'key', 'token', '.pem', '.key', 'id_rsa']):
                    sensitive_files.append(os.path.join(root, file))
        
        if sensitive_files:
            print(f"Found {len(sensitive_files)} potentially sensitive files:")
            for file in sensitive_files:
                print(f"  {file}")
        else:
            print("No sensitive files detected in current directory")
    
    def threat_intelligence_check(self):
        """
        Check for known malicious IPs using threat intelligence
        """
        print("\n--- THREAT INTELLIGENCE CHECK ---")
        print("This feature would typically connect to threat intelligence feeds")
        print("to check for known malicious IPs and domains.")
        print("\nFor demonstration, here are some known threat intelligence sources:")
        print("  - AbuseIPDB")
        print("  - VirusTotal")
        print("  - Emerging Threats")
        print("  - OSINT Framework")
        print("\nNote: This requires API keys and network connectivity.")


def main():
    """
    Main function to run the cybersecurity suite
    """
    parser = argparse.ArgumentParser(description='Comprehensive Cybersecurity Suite')
    parser.add_argument('--scan', action='store_true', help='Run comprehensive security scan')
    parser.add_argument('--interactive', '-i', action='store_true', help='Run in interactive mode')
    parser.add_argument('--version', '-v', action='store_true', help='Show version information')
    
    args = parser.parse_args()
    
    suite = CybersecuritySuite()
    
    if args.version:
        print("Cybersecurity Suite v1.0")
        print("A comprehensive tool for system security analysis and protection")
        return
    
    if args.scan:
        suite.run_comprehensive_scan()
    elif args.interactive:
        suite.interactive_mode()
    else:
        # Default to interactive mode if no arguments provided
        print("Welcome to the Cybersecurity Suite!")
        print("Use --scan for a comprehensive security scan")
        print("Use --interactive or -i for interactive mode")
        print("Use --version or -v for version information")
        suite.interactive_mode()


if __name__ == "__main__":
    main()