"""
fban2 - Firewall Ban System
This module provides functionality for managing firewall bans and blocking malicious IPs.
"""

import subprocess
import re
import sys
import time
from datetime import datetime, timedelta


class FBan2:
    """
    Firewall Ban System - fban2
    A module for managing IP bans and firewall rules to block malicious traffic.
    """
    
    def __init__(self):
        self.banned_ips = set()
        self.ban_log = []
    
    def ban_ip(self, ip_address, reason="No reason provided", duration=None):
        """
        Ban an IP address using iptables or ufw
        """
        try:
            # First, try using UFW if available
            result = subprocess.run(['which', 'ufw'], capture_output=True, text=True)
            if result.returncode == 0:
                # UFW is available
                cmd = ['ufw', 'deny', 'from', ip_address]
                subprocess.run(cmd, check=True)
                method = "ufw"
            else:
                # Fallback to iptables
                cmd = ['iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP']
                subprocess.run(cmd, check=True)
                method = "iptables"
            
            # Log the ban
            ban_info = {
                'ip': ip_address,
                'timestamp': datetime.now(),
                'reason': reason,
                'method': method,
                'duration': duration
            }
            
            self.banned_ips.add(ip_address)
            self.ban_log.append(ban_info)
            
            print(f"IP {ip_address} has been banned using {method}. Reason: {reason}")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"Error banning IP {ip_address}: {e}")
            return False
        except Exception as e:
            print(f"Unexpected error banning IP {ip_address}: {e}")
            return False
    
    def unban_ip(self, ip_address):
        """
        Unban an IP address
        """
        try:
            # Check if UFW is available
            result = subprocess.run(['which', 'ufw'], capture_output=True, text=True)
            if result.returncode == 0:
                # UFW is available - remove the rule
                cmd = ['ufw', 'delete', 'deny', 'from', ip_address]
                subprocess.run(cmd, check=True, input='y\n', text=True)
                method = "ufw"
            else:
                # Fallback to iptables
                cmd = ['iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP']
                subprocess.run(cmd, check=True)
                method = "iptables"
            
            # Remove from banned set
            if ip_address in self.banned_ips:
                self.banned_ips.remove(ip_address)
            
            print(f"IP {ip_address} has been unbanned from {method}")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"Error unbanning IP {ip_address}: {e}")
            return False
        except Exception as e:
            print(f"Unexpected error unbanning IP {ip_address}: {e}")
            return False
    
    def check_ip_status(self, ip_address):
        """
        Check if an IP is currently banned
        """
        # Check using iptables
        try:
            result = subprocess.run(['iptables', '-L', '-n'], capture_output=True, text=True)
            if ip_address in result.stdout:
                return True
        except:
            pass
        
        # Also check in our internal list
        return ip_address in self.banned_ips
    
    def list_banned_ips(self):
        """
        List all currently banned IPs
        """
        try:
            # Get bans from iptables
            result = subprocess.run(['iptables', '-L', 'INPUT', '-n'], capture_output=True, text=True)
            iptables_bans = set()
            
            # Extract IP addresses from iptables output
            for line in result.stdout.split('\n'):
                # Look for DROP rules
                if 'DROP' in line:
                    # Extract IP addresses
                    matches = re.findall(r'\d+\.\d+\.\d+\.\d+', line)
                    iptables_bans.update(matches)
            
            # Combine with our internal list
            all_bans = iptables_bans.union(self.banned_ips)
            return list(all_bans)
            
        except Exception as e:
            print(f"Error listing banned IPs: {e}")
            return list(self.banned_ips)
    
    def auto_ban_from_logs(self, log_file_path, threshold=10, time_window=300):
        """
        Automatically ban IPs that exceed a threshold of connections in a time window
        """
        try:
            # Read log file
            with open(log_file_path, 'r') as f:
                log_lines = f.readlines()
            
            # Extract IP addresses and timestamps
            ip_attempts = {}
            
            for line in log_lines:
                # Common log formats - adjust as needed
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    ip = ip_match.group(1)
                    # Add to attempts counter
                    if ip not in ip_attempts:
                        ip_attempts[ip] = []
                    ip_attempts[ip].append(datetime.now())
            
            # Check for IPs exceeding threshold
            for ip, attempts in ip_attempts.items():
                # Count attempts in the last time window
                recent_attempts = [
                    attempt for attempt in attempts
                    if datetime.now() - attempt < timedelta(seconds=time_window)
                ]
                
                if len(recent_attempts) >= threshold:
                    if not self.check_ip_status(ip):
                        self.ban_ip(ip, f"Auto-banned: {len(recent_attempts)} attempts in {time_window} seconds")
            
        except FileNotFoundError:
            print(f"Log file {log_file_path} not found")
        except Exception as e:
            print(f"Error processing log file: {e}")
    
    def cleanup_expired_bans(self):
        """
        Remove bans that have expired based on duration
        """
        current_time = datetime.now()
        expired_bans = []
        
        for ban_info in self.ban_log:
            if ban_info['duration'] and ban_info['timestamp'] + timedelta(seconds=ban_info['duration']) < current_time:
                expired_bans.append(ban_info['ip'])
        
        for ip in expired_bans:
            self.unban_ip(ip)
            print(f"Expired ban removed for IP: {ip}")


def main():
    """
    Main function to demonstrate fban2 functionality
    """
    fban = FBan2()
    
    print("fban2 - Firewall Ban System")
    print("Available commands:")
    print("  ban <IP> [reason] - Ban an IP address")
    print("  unban <IP> - Unban an IP address")
    print("  status <IP> - Check if IP is banned")
    print("  list - List all banned IPs")
    print("  example - Run example usage")
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "ban" and len(sys.argv) > 2:
            ip = sys.argv[2]
            reason = sys.argv[3] if len(sys.argv) > 3 else "Manual ban"
            fban.ban_ip(ip, reason)
        
        elif command == "unban" and len(sys.argv) > 2:
            ip = sys.argv[2]
            fban.unban_ip(ip)
        
        elif command == "status" and len(sys.argv) > 2:
            ip = sys.argv[2]
            status = fban.check_ip_status(ip)
            print(f"IP {ip} is {'banned' if status else 'not banned'}")
        
        elif command == "list":
            banned = fban.list_banned_ips()
            print("Banned IPs:")
            for ip in banned:
                print(f"  {ip}")
        
        elif command == "example":
            print("Running example usage...")
            # Example usage would go here
            print("Example: fban2 ban 192.168.1.100 'Suspicious activity'")
    
    else:
        print("\nTo use fban2, run with a command:")
        print("python fban2.py ban 192.168.1.100 'Reason for ban'")


if __name__ == "__main__":
    main()