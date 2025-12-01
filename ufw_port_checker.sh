#!/bin/bash
# UFW Port Verification Module
# This module provides functionality to check open ports using UFW (Uncomplicated Firewall).

# Check if UFW is active and running
check_ufw_status() {
    if command -v ufw &> /dev/null; then
        ufw status
    else
        echo "UFW command not found. Please install UFW first."
    fi
}

# List all open ports using UFW status
list_open_ports() {
    local ufw_status
    ufw_status=$(check_ufw_status)
    
    if [[ "$ufw_status" == *"not found"* ]] || [[ "$ufw_status" == *"not running"* ]]; then
        echo "$ufw_status"
        return 1
    fi
    
    # Extract port information from UFW status
    echo "$ufw_status" | while IFS= read -r line; do
        # Look for lines that contain port information
        if [[ "$line" =~ ALLOW ]] || [[ "$line" =~ LIMIT ]]; then
            # Extract port numbers using regex
            local port_matches
            port_matches=$(echo "$line" | grep -oE '[0-9]+(:[0-9]+)?/(tcp|udp|any)')
            
            if [[ -n "$port_matches" ]]; then
                while IFS= read -r match; do
                    if [[ -n "$match" ]]; then
                        local port=$(echo "$match" | cut -d'/' -f1)
                        local protocol=$(echo "$match" | cut -d'/' -f2)
                        local status="open"
                        if [[ "$line" =~ LIMIT ]]; then
                            status="limited"
                        fi
                        echo "  Port: $port, Protocol: $protocol, Status: $status"
                    fi
                done < <(echo "$port_matches" | tr ' ' '\n')
            fi
        fi
    done
    
    # If no ports were found, mention it
    if ! echo "$ufw_status" | grep -qE "(ALLOW|LIMIT)"; then
        echo "  No open ports found (or UFW not running)"
    fi
}

# Check if a specific port is open
is_port_open() {
    local port_number="$1"
    local ufw_status
    ufw_status=$(check_ufw_status)
    
    if [[ "$ufw_status" == *"not found"* ]] || [[ "$ufw_status" == *"not running"* ]]; then
        echo "$ufw_status"
        return 1
    fi
    
    # Check if the port is in the UFW status
    if echo "$ufw_status" | grep -q "$port_number"; then
        return 0  # Port is open
    else
        return 1  # Port is not open
    fi
}

# Scan and return all open ports
scan_for_open_ports() {
    list_open_ports
}

# Check security status of a specific port
check_port_security() {
    local port_number="$1"
    local ufw_status
    ufw_status=$(check_ufw_status)
    
    if [[ "$ufw_status" == *"not found"* ]] || [[ "$ufw_status" == *"not running"* ]]; then
        echo "$ufw_status"
        return 1
    fi
    
    # Check if the port is explicitly allowed
    if is_port_open "$port_number"; then
        echo "Port $port_number is open. Ensure it's necessary and properly secured."
    else
        echo "Port $port_number is not explicitly allowed by UFW."
    fi
}

# Make functions available when sourced
export -f check_ufw_status
export -f list_open_ports
export -f is_port_open
export -f scan_for_open_ports
export -f check_port_security