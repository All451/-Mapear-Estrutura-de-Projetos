"""
Security Suite - Main Module
This module integrates all security modules: cybersecurity, UFW port checker, and fban2.
"""

from cybersecurity_module import *
from ufw_port_checker import *
from fban2 import FBan2
from docker_exposure_checker import DockerExposureChecker
import sys


def display_menu():
    """Display the main menu for the security suite"""
    print("\n" + "="*50)
    print("CYBERSECURITY SUITE")
    print("="*50)
    print("1. General Security Audit")
    print("2. UFW Port Verification")
    print("3. Firewall Ban Management (fban2)")
    print("4. Docker Container Exposure Check")
    print("5. Run Complete Security Scan")
    print("6. Exit")
    print("="*50)


def run_security_audit():
    """Run general security audit"""
    print("\n--- GENERAL SECURITY AUDIT ---")
    security_audit()
    check_system_integrity()
    print("Security audit completed.")


def run_ufw_check():
    """Run UFW port verification"""
    print("\n--- UFW PORT VERIFICATION ---")
    print("Current UFW Status:")
    print(check_ufw_status())
    
    print("\nOpen ports:")
    ports = list_open_ports()
    if isinstance(ports, list):
        if ports:
            for port in ports:
                print(f"  Port: {port['port']}, Protocol: {port['protocol']}, Status: {port['status']}")
        else:
            print("  No open ports found (or UFW not running)")
    else:
        print(ports)


def run_fban_management():
    """Run firewall ban management interface"""
    print("\n--- FIREWALL BAN MANAGEMENT (fban2) ---")
    fban = FBan2()
    
    while True:
        print("\nfban2 Options:")
        print("  1. Ban an IP address")
        print("  2. Unban an IP address")
        print("  3. Check IP status")
        print("  4. List banned IPs")
        print("  5. Go back to main menu")
        
        choice = input("Select an option (1-5): ").strip()
        
        if choice == '1':
            ip = input("Enter IP address to ban: ").strip()
            reason = input("Enter reason for ban (optional): ").strip() or "No reason provided"
            fban.ban_ip(ip, reason)
        elif choice == '2':
            ip = input("Enter IP address to unban: ").strip()
            fban.unban_ip(ip)
        elif choice == '3':
            ip = input("Enter IP address to check: ").strip()
            status = fban.check_ip_status(ip)
            print(f"IP {ip} is {'banned' if status else 'not banned'}")
        elif choice == '4':
            banned_ips = fban.list_banned_ips()
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


def run_docker_exposure_check():
    """Run Docker container exposure check"""
    print("\n--- DOCKER CONTAINER EXPOSURE CHECK ---")
    checker = DockerExposureChecker()
    
    try:
        print(checker.generate_report())
        print("\n" + "\n".join(checker.get_security_recommendations()))
    except Exception as e:
        print(f"Error checking Docker exposure: {e}")
        print("Make sure Docker is installed and running, and you have proper permissions.")


def run_complete_scan():
    """Run a complete security scan using all modules"""
    print("\n--- COMPLETE SECURITY SCAN ---")
    
    print("Running general security audit...")
    security_audit()
    check_system_integrity()
    
    print("\nChecking firewall and ports...")
    print("UFW Status:")
    print(check_ufw_status())
    
    print("\nOpen ports:")
    ports = list_open_ports()
    if isinstance(ports, list):
        if ports:
            for port in ports:
                print(f"  Port: {port['port']}, Protocol: {port['protocol']}, Status: {port['status']}")
        else:
            print("  No open ports found (or UFW not running)")
    else:
        print(ports)
    
    print("\nChecking Docker containers...")
    checker = DockerExposureChecker()
    try:
        print(checker.generate_report())
    except Exception as e:
        print(f"Error checking Docker exposure: {e}")
        print("Make sure Docker is installed and running, and you have proper permissions.")
    
    print("\nChecking active bans...")
    fban = FBan2()
    banned_ips = fban.list_banned_ips()
    print(f"Total banned IPs: {len(banned_ips)}")
    
    print("\nComplete security scan finished.")


def main():
    """Main function to run the security suite"""
    print("Welcome to the Cybersecurity Suite!")
    
    while True:
        display_menu()
        choice = input("Select an option (1-6): ").strip()
        
        if choice == '1':
            run_security_audit()
        elif choice == '2':
            run_ufw_check()
        elif choice == '3':
            run_fban_management()
        elif choice == '4':
            run_docker_exposure_check()
        elif choice == '5':
            run_complete_scan()
        elif choice == '6':
            print("Exiting Cybersecurity Suite. Stay secure!")
            sys.exit(0)
        else:
            print("Invalid option. Please select 1-6.")
        
        input("\nPress Enter to continue...")


if __name__ == "__main__":
    main()