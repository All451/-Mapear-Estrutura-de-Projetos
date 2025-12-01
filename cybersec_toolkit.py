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

def check_dependencies():
    """
    Check if required dependencies are available
    """
    print("Checking dependencies...")
    
    # Check Python modules
    required_modules = ['docker', 'requests']
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
    required_commands = ['ufw', 'docker']
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
    
    return True

def run_python_suite():
    """
    Run the Python-based cybersecurity suite
    """
    try:
        from cybersecurity_suite import CybersecuritySuite
        suite = CybersecuritySuite()
        
        parser = argparse.ArgumentParser(description='Comprehensive Cybersecurity Suite')
        parser.add_argument('--scan', action='store_true', help='Run comprehensive security scan')
        parser.add_argument('--interactive', '-i', action='store_true', help='Run in interactive mode')
        parser.add_argument('--version', '-v', action='store_true', help='Show version information')
        
        args = parser.parse_args()
        
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
            
    except ImportError as e:
        print(f"Error importing cybersecurity suite: {e}")
        print("Make sure all required modules are installed.")
        sys.exit(1)

def run_shell_suite():
    """
    Run the shell-based cybersecurity suite
    """
    try:
        # Make the shell script executable
        os.chmod('cybersecurity_suite.sh', 0o755)
        
        # Run the shell script
        if len(sys.argv) > 1:
            subprocess.run(['bash', 'cybersecurity_suite.sh'] + sys.argv[1:])
        else:
            subprocess.run(['bash', 'cybersecurity_suite.sh'])
    except Exception as e:
        print(f"Error running shell suite: {e}")
        sys.exit(1)

def main():
    """
    Main function to run the cybersecurity toolkit
    """
    print("🛡️  CYBERSECURITY TOOLKIT v1.0 🛡️")
    print("A comprehensive tool for system security analysis and protection")
    print("="*65)
    
    # Check dependencies
    deps_ok = check_dependencies()
    if not deps_ok:
        print("\n⚠️  Some dependencies are missing, but the toolkit can still run with limited functionality.")
        response = input("Continue anyway? (y/n): ").strip().lower()
        if response not in ['y', 'yes', '']:
            sys.exit(0)
    
    # Determine which suite to run based on arguments or availability
    if len(sys.argv) > 1:
        if sys.argv[1] in ['--scan', '--interactive', '-i', '--version', '-v', '--help', '-h']:
            # Use Python suite for specific commands
            run_python_suite()
        else:
            # Use shell suite for other commands
            run_shell_suite()
    else:
        # Default to Python suite with interactive mode
        run_python_suite()

if __name__ == "__main__":
    main()