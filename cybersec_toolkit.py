#!/usr/bin/env python3
"""
Cybersecurity Toolkit - Main Entry Point
This is the main entry point for the comprehensive cybersecurity toolkit.
"""
import os
import sys
import subprocess
import argparse
from datetime import datetime

# Import our new modules
from cybersec_config import CybersecConfig
from cybersec_logging import CybersecLogger
from cybersecurity_suite import CybersecuritySuite


class CybersecToolkit:
    """
    Main class for the Cybersecurity Toolkit
    """
    
    def __init__(self):
        """
        Initialize the toolkit
        """
        self.config = CybersecConfig()
        self.logger = CybersecLogger(
            name="cybersec_toolkit",
            log_file="/tmp/cybersec_toolkit.log",
            level=self.config.get('general.log_level', 'INFO')
        )
        self.suite = CybersecuritySuite()
    
    def run_comprehensive_scan(self):
        """
        Run a comprehensive security scan
        """
        self.logger.log_security_event(
            "scan_start", 
            "Starting comprehensive security scan", 
            "INFO"
        )
        
        try:
            self.suite.run_comprehensive_scan()
            self.logger.log_security_event(
                "scan_complete", 
                "Comprehensive security scan completed", 
                "INFO"
            )
        except Exception as e:
            self.logger.log_security_event(
                "scan_error", 
                f"Error during comprehensive scan: {str(e)}", 
                "ERROR"
            )
            raise
    
    def run_interactive_mode(self):
        """
        Run the toolkit in interactive mode
        """
        self.logger.log_security_event(
            "interactive_start", 
            "Starting interactive mode", 
            "INFO"
        )
        
        try:
            self.suite.interactive_mode()
            self.logger.log_security_event(
                "interactive_exit", 
                "Exiting interactive mode", 
                "INFO"
            )
        except Exception as e:
            self.logger.log_security_event(
                "interactive_error", 
                f"Error in interactive mode: {str(e)}", 
                "ERROR"
            )
            raise
    
    def show_version(self):
        """
        Show version information
        """
        try:
            with open("VERSION", "r") as f:
                version = f.read().strip()
        except FileNotFoundError:
            version = "unknown"
        
        print(f"Cybersecurity Toolkit v{version}")
        print("A comprehensive tool for system security analysis and protection")
    
    def show_help(self):
        """
        Show help information
        """
        print("Cybersecurity Toolkit - Help")
        print("=" * 40)
        print("Available commands:")
        print("  --scan, -s          Run comprehensive security scan")
        print("  --interactive, -i   Run in interactive mode")
        print("  --version, -v       Show version information")
        print("  --help, -h          Show this help message")
        print("")
        print("Examples:")
        print("  python3 cybersec_toolkit.py --scan")
        print("  python3 cybersec_toolkit.py -i")
        print("  python3 cybersec_toolkit.py --version")


def check_dependencies():
    """
    Check if required dependencies are available
    """
    print("Checking dependencies...")
    
    # Check Python modules
    required_modules = ['docker', 'requests', 'yaml']
    missing_modules = []
    
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing_modules.append(module)
    
    if missing_modules:
        print(f"Missing Python modules: {', '.join(missing_modules)}")
        print("Install with: pip install " + " ".join(missing_modules))
        return False
    
    # Check system commands
    required_commands = ['ufw', 'docker', 'tree', 'jq']
    missing_commands = []
    
    for cmd in required_commands:
        result = subprocess.run(['which', cmd], capture_output=True, text=True)
        if result.returncode != 0:
            missing_commands.append(cmd)
    
    if missing_commands:
        print(f"Missing system commands: {', '.join(missing_commands)}")
        for cmd in missing_commands:
            if cmd == 'ufw':
                print("  Install with: sudo apt install ufw")
            elif cmd == 'docker':
                print("  Install with: Follow official Docker installation guide")
            elif cmd == 'tree':
                print("  Install with: sudo apt install tree")
            elif cmd == 'jq':
                print("  Install with: sudo apt install jq")
    
    return True


def main():
    """
    Main function to run the cybersecurity toolkit
    """
    print("🛡️  CYBERSECURITY TOOLKIT v3.0.0 🛡️")
    print("A comprehensive tool for system security analysis and protection")
    print("="*65)
    
    # Check dependencies
    deps_ok = check_dependencies()
    if not deps_ok:
        print("\n⚠️  Some dependencies are missing, but the toolkit can still run with limited functionality.")
        response = input("Continue anyway? (y/n): ").strip().lower()
        if response not in ['y', 'yes', '']:
            sys.exit(0)
    
    # Parse arguments using the new argument parser
    parser = argparse.ArgumentParser(
        description='Comprehensive Cybersecurity Toolkit',
        prog='cybersec_toolkit'
    )
    
    # Add arguments
    parser.add_argument(
        '--scan', 
        action='store_true', 
        help='Run comprehensive security scan'
    )
    parser.add_argument(
        '--interactive', '-i', 
        action='store_true', 
        help='Run in interactive mode'
    )
    parser.add_argument(
        '--version', '-v', 
        action='store_true', 
        help='Show version information'
    )
    parser.add_argument(
        '--help-cmd', '-H', 
        action='store_true', 
        help='Show help information'
    )
    
    # Parse arguments
    args = parser.parse_args()
    
    # Create toolkit instance
    toolkit = CybersecToolkit()
    
    # Handle arguments
    if args.version:
        toolkit.show_version()
    elif args.help_cmd:
        toolkit.show_help()
    elif args.scan:
        toolkit.run_comprehensive_scan()
    elif args.interactive:
        toolkit.run_interactive_mode()
    else:
        # Default to interactive mode if no arguments provided
        print("Welcome to the Cybersecurity Toolkit!")
        print("Use --scan for a comprehensive security scan")
        print("Use --interactive or -i for interactive mode")
        print("Use --version or -v for version information")
        toolkit.run_interactive_mode()


if __name__ == "__main__":
    main()