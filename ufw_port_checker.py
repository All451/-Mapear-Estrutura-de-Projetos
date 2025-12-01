"""
UFW Port Verification Module
This module provides functionality to check open ports using UFW (Uncomplicated Firewall).
"""

import subprocess
import re
import sys


def check_ufw_status():
    """Check if UFW is active and running"""
    try:
        result = subprocess.run(['ufw', 'status'], capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError:
        return "UFW is not installed or not running properly"
    except FileNotFoundError:
        return "UFW command not found. Please install UFW first."


def list_open_ports():
    """List all open ports using UFW status"""
    ufw_status = check_ufw_status()
    
    if "not found" in ufw_status or "not running" in ufw_status:
        return {"error": ufw_status}
    
    # Extract port information from UFW status
    lines = ufw_status.split('\n')
    open_ports = []
    
    for line in lines:
        # Look for lines that contain port information
        if 'ALLOW' in line or 'LIMIT' in line:
            # Extract port numbers using regex
            port_matches = re.findall(r'(\d+(?::\d+)?)/(tcp|udp|any)', line)
            for port, protocol in port_matches:
                open_ports.append({
                    "port": port,
                    "protocol": protocol,
                    "status": "open" if "ALLOW" in line else "limited"
                })
    
    return open_ports


def is_port_open(port_number):
    """Check if a specific port is open"""
    open_ports = list_open_ports()
    
    if isinstance(open_ports, dict) and "error" in open_ports:
        return open_ports
    
    for port_info in open_ports:
        if str(port_number) in port_info['port']:
            return True
    
    return False


def scan_for_open_ports():
    """Scan and return all open ports"""
    return list_open_ports()


def check_port_security(port_number):
    """Check security status of a specific port"""
    ufw_status = check_ufw_status()
    
    if "not found" in ufw_status or "not running" in ufw_status:
        return {"error": ufw_status}
    
    # Check if the port is explicitly allowed
    if is_port_open(port_number):
        return {
            "port": port_number,
            "status": "open",
            "security_advice": f"Port {port_number} is open. Ensure it's necessary and properly secured."
        }
    else:
        return {
            "port": port_number,
            "status": "closed/filtered",
            "security_advice": f"Port {port_number} is not explicitly allowed by UFW."
        }


if __name__ == "__main__":
    print("UFW Port Verification Module")
    print("Current UFW Status:")
    print(check_ufw_status())
    print("\nOpen ports:")
    ports = list_open_ports()
    if isinstance(ports, list):
        for port in ports:
            print(f"Port: {port['port']}, Protocol: {port['protocol']}, Status: {port['status']}")
    else:
        print(ports)