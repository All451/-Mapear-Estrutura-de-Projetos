"""
UFW Port Verification Module
This module provides functionality to check open ports using UFW (Uncomplicated Firewall).
"""

import subprocess
import re
import sys
import socket
from typing import Dict, List, Union, Optional
from cybersecurity_module import run_security_command


def check_ufw_status():
    """Check if UFW is active and running"""
    try:
        # Use the safe command execution function
        result = run_security_command(['ufw', 'status'])
        if result.returncode == 0:
            return result.stdout
        else:
            return f"UFW is not installed or not running properly: {result.stderr}"
    except ValueError as e:
        return f"Command validation error: {e}"
    except subprocess.TimeoutExpired:
        return "Command timed out while checking UFW status"
    except Exception as e:
        return f"Error checking UFW status: {e}"


def list_open_ports():
    """List all open ports using UFW status"""
    ufw_status = check_ufw_status()
    
    if "not found" in ufw_status or "not running" in ufw_status or "error" in ufw_status.lower():
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
                    "status": "open" if "ALLOW" in line else "limited",
                    "rule": line.strip()  # Include the full rule for context
                })
    
    return open_ports


def is_port_open(port_number: Union[int, str]) -> Union[bool, Dict]:
    """Check if a specific port is open with input validation"""
    # Validate input
    try:
        port_num = int(port_number)
        if not (1 <= port_num <= 65535):
            raise ValueError("Port number must be between 1 and 65535")
    except ValueError:
        return {"error": f"Invalid port number: {port_number}"}
    
    open_ports = list_open_ports()
    
    if isinstance(open_ports, dict) and "error" in open_ports:
        return open_ports
    
    for port_info in open_ports:
        port_range = port_info['port']
        # Handle port ranges like "8000:9000"
        if ':' in port_range:
            start, end = map(int, port_range.split(':'))
            if start <= port_num <= end:
                return True
        elif str(port_num) == port_range:
            return True
        elif str(port_num) in port_range and len(port_range) > len(str(port_num)):
            # Additional check to avoid matching partial numbers (e.g. 80 in 1800)
            # Check if the port number is a complete match, not just a substring
            continue
    
    return False


def scan_for_open_ports():
    """Scan and return all open ports"""
    return list_open_ports()


def check_port_security(port_number: Union[int, str]) -> Dict:
    """Check security status of a specific port with enhanced security analysis"""
    # Validate input
    try:
        port_num = int(port_number)
        if not (1 <= port_num <= 65535):
            raise ValueError("Port number must be between 1 and 65535")
    except ValueError:
        return {"error": f"Invalid port number: {port_number}"}
    
    ufw_status = check_ufw_status()
    
    if "not found" in ufw_status or "not running" in ufw_status or "error" in ufw_status.lower():
        return {"error": ufw_status}
    
    # Check if the port is explicitly allowed
    is_open = is_port_open(port_num)
    if isinstance(is_open, dict) and "error" in is_open:
        return is_open
    
    # Determine if this is a well-known service port
    well_known_ports = {
        20: "FTP Data", 21: "FTP Control", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
        993: "IMAPS", 995: "POP3S", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
        6379: "Redis", 27017: "MongoDB"
    }
    
    service_name = well_known_ports.get(port_num, "Unknown")
    
    if is_open:
        # Check if it's a potentially dangerous port
        dangerous_ports = [21, 23, 135, 139, 445, 3389]  # FTP, Telnet, SMB, RDP
        if port_num in dangerous_ports:
            security_advice = f"CRITICAL: Port {port_num} ({service_name}) is open and potentially dangerous. Consider closing unless absolutely necessary."
        else:
            security_advice = f"Port {port_num} ({service_name}) is open. Ensure it's necessary and properly secured."
        
        return {
            "port": port_num,
            "service": service_name,
            "status": "open",
            "security_level": "dangerous" if port_num in dangerous_ports else "moderate",
            "security_advice": security_advice
        }
    else:
        return {
            "port": port_num,
            "service": service_name,
            "status": "closed/filtered",
            "security_level": "secure",
            "security_advice": f"Port {port_num} ({service_name}) is not explicitly allowed by UFW."
        }


def check_listening_ports():
    """Check for actually listening ports on the system (not just UFW rules)"""
    try:
        # Use ss command to check for listening ports (safer than netstat)
        result = run_security_command(['ss', '-tuln'])
        if result.returncode != 0:
            return {"error": f"Failed to get listening ports: {result.stderr}"}
        
        lines = result.stdout.split('\n')
        listening_ports = []
        
        for line in lines[1:]:  # Skip header
            if line.strip():
                parts = line.split()
                if len(parts) >= 5:
                    protocol = parts[0]
                    local_addr = parts[4]
                    # Extract port from address:port format
                    if ':' in local_addr:
                        port = local_addr.split(':')[-1]
                        if port.isdigit():
                            listening_ports.append({
                                "port": int(port),
                                "protocol": protocol,
                                "address": local_addr
                            })
        
        return listening_ports
    except ValueError as e:
        return {"error": f"Command validation error: {e}"}
    except Exception as e:
        return {"error": f"Error checking listening ports: {e}"}


def get_port_security_report() -> Dict:
    """Generate a comprehensive port security report"""
    ufw_ports = list_open_ports()
    system_ports = check_listening_ports()
    
    report = {
        "timestamp": __import__('datetime').datetime.now().isoformat(),
        "ufw_configured": "not found" not in check_ufw_status().lower(),
        "open_ports_ufw": ufw_ports if isinstance(ufw_ports, list) else [],
        "listening_ports_system": system_ports if isinstance(system_ports, list) else [],
        "recommendations": []
    }
    
    # Identify ports that are listening but not explicitly allowed by UFW
    if isinstance(system_ports, list) and isinstance(ufw_ports, list):
        listening_set = {p['port'] for p in system_ports}
        ufw_set = set()
        for ufw_port in ufw_ports:
            port_str = ufw_port['port']
            if ':' in port_str:  # Handle port ranges
                start, end = map(int, port_str.split(':'))
                ufw_set.update(range(start, end + 1))
            else:
                ufw_set.add(int(port_str))
        
        exposed_ports = listening_set - ufw_set
        if exposed_ports:
            report["recommendations"].append(
                f"CRITICAL: {len(exposed_ports)} ports are listening but not controlled by UFW: {sorted(exposed_ports)}"
            )
    
    # Check for dangerous ports in UFW rules
    dangerous_ufw_ports = []
    for port_info in report["open_ports_ufw"]:
        port_str = port_info['port']
        if ':' in port_str:
            start, end = map(int, port_str.split(':'))
            port_range = range(start, end + 1)
        else:
            port_range = [int(port_str)]
        
        dangerous_ports = [21, 23, 135, 139, 445, 3389]
        for port in port_range:
            if port in dangerous_ports:
                dangerous_ufw_ports.append(port)
    
    if dangerous_ufw_ports:
        report["recommendations"].append(
            f"Dangerous ports open in UFW: {dangerous_ufw_ports}. Consider restricting access."
        )
    
    return report


if __name__ == "__main__":
    print("UFW Port Verification Module")
    print("Current UFW Status:")
    print(check_ufw_status())
    print("\nOpen ports (UFW):")
    ports = list_open_ports()
    if isinstance(ports, list):
        for port in ports:
            print(f"Port: {port['port']}, Protocol: {port['protocol']}, Status: {port['status']}")
    else:
        print(ports)
    
    print("\nListening ports (System):")
    listening = check_listening_ports()
    if isinstance(listening, list):
        for port in listening:
            print(f"Port: {port['port']}, Protocol: {port['protocol']}, Address: {port['address']}")
    else:
        print(listening)
    
    print("\nPort Security Report:")
    report = get_port_security_report()
    print(f"UFW Configured: {report['ufw_configured']}")
    print(f"Open ports in UFW: {len(report['open_ports_ufw'])}")
    print(f"Listening ports on system: {len(report['listening_ports_system'])}")
    print("Recommendations:")
    for rec in report['recommendations']:
        print(f"  - {rec}")