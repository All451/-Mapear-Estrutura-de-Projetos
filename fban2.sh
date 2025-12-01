#!/bin/bash
# fban2 - Firewall Ban System
# This script provides functionality for managing firewall bans and blocking malicious IPs.

# Global variables to track banned IPs
declare -a banned_ips=()
declare -a ban_reasons=()
declare -a ban_methods=()

# Initialize fban2
fban2_init() {
    # Load existing bans from iptables
    load_existing_bans
}

# Load existing bans from iptables
load_existing_bans() {
    # Check if iptables is available
    if command -v iptables &> /dev/null; then
        # Extract banned IPs from iptables
        local iptables_output
        iptables_output=$(iptables -L -n 2>/dev/null)
        
        # Extract IP addresses from iptables DROP rules
        echo "$iptables_output" | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | while read -r ip; do
            if [[ ! " ${banned_ips[@]} " =~ " ${ip} " ]]; then
                banned_ips+=("$ip")
                ban_reasons+=("Previously banned via iptables")
                ban_methods+=("iptables")
            fi
        done
    fi
}

# Ban an IP address using iptables or ufw
ban_ip() {
    local ip_address="$1"
    local reason="${2:-No reason provided}"
    
    # Validate IP address format
    if ! validate_ip "$ip_address"; then
        echo "Invalid IP address format: $ip_address"
        return 1
    fi
    
    # Check if IP is already banned
    if [[ " ${banned_ips[@]} " =~ " ${ip_address} " ]]; then
        echo "IP $ip_address is already banned"
        return 1
    fi
    
    # First, try using UFW if available
    if command -v ufw &> /dev/null; then
        if ufw deny from "$ip_address" 2>/dev/null; then
            banned_ips+=("$ip_address")
            ban_reasons+=("$reason")
            ban_methods+=("ufw")
            echo "IP $ip_address has been banned using ufw. Reason: $reason"
            return 0
        fi
    fi
    
    # Fallback to iptables
    if command -v iptables &> /dev/null; then
        if iptables -A INPUT -s "$ip_address" -j DROP 2>/dev/null; then
            banned_ips+=("$ip_address")
            ban_reasons+=("$reason")
            ban_methods+=("iptables")
            echo "IP $ip_address has been banned using iptables. Reason: $reason"
            return 0
        else
            echo "Error banning IP $ip_address: failed to add iptables rule"
            return 1
        fi
    else
        echo "Error banning IP $ip_address: neither ufw nor iptables available"
        return 1
    fi
}

# Unban an IP address
unban_ip() {
    local ip_address="$1"
    
    # Validate IP address format
    if ! validate_ip "$ip_address"; then
        echo "Invalid IP address format: $ip_address"
        return 1
    fi
    
    # Check if IP is currently banned
    local ip_index=-1
    for i in "${!banned_ips[@]}"; do
        if [[ "${banned_ips[$i]}" == "$ip_address" ]]; then
            ip_index=$i
            break
        fi
    done
    
    if [[ $ip_index -eq -1 ]]; then
        echo "IP $ip_address is not currently banned"
        return 1
    fi
    
    # Check if UFW is available
    if command -v ufw &> /dev/null; then
        # Try to remove the rule using UFW
        if ufw delete deny from "$ip_address" <<< $'y\n' 2>/dev/null; then
            # Remove from our arrays
            unset 'banned_ips[$ip_index]'
            unset 'ban_reasons[$ip_index]'
            unset 'ban_methods[$ip_index]'
            # Re-index arrays
            banned_ips=("${banned_ips[@]}")
            ban_reasons=("${ban_reasons[@]}")
            ban_methods=("${ban_methods[@]}")
            
            echo "IP $ip_address has been unbanned using ufw"
            return 0
        fi
    fi
    
    # Fallback to iptables
    if command -v iptables &> /dev/null; then
        if iptables -D INPUT -s "$ip_address" -j DROP 2>/dev/null; then
            # Remove from our arrays
            unset 'banned_ips[$ip_index]'
            unset 'ban_reasons[$ip_index]'
            unset 'ban_methods[$ip_index]'
            # Re-index arrays
            banned_ips=("${banned_ips[@]}")
            ban_reasons=("${ban_reasons[@]}")
            ban_methods=("${ban_methods[@]}")
            
            echo "IP $ip_address has been unbanned using iptables"
            return 0
        else
            echo "Error unbanning IP $ip_address: failed to remove iptables rule"
            return 1
        fi
    else
        echo "Error unbanning IP $ip_address: neither ufw nor iptables available"
        return 1
    fi
}

# Check if an IP is currently banned
check_ip_status() {
    local ip_address="$1"
    
    # Validate IP address format
    if ! validate_ip "$ip_address"; then
        echo "Invalid IP address format: $ip_address"
        return 1
    fi
    
    # Check using iptables
    if command -v iptables &> /dev/null; then
        local result
        result=$(iptables -L -n 2>/dev/null | grep -o "$ip_address" | head -1)
        if [[ -n "$result" ]]; then
            echo "IP $ip_address is banned"
            return 0
        fi
    fi
    
    # Also check in our internal list
    if [[ " ${banned_ips[@]} " =~ " ${ip_address} " ]]; then
        echo "IP $ip_address is banned"
        return 0
    else
        echo "IP $ip_address is not banned"
        return 1
    fi
}

# List all currently banned IPs
list_banned_ips() {
    # Get bans from iptables
    local iptables_bans=()
    if command -v iptables &> /dev/null; then
        # Extract IP addresses from iptables output
        while IFS= read -r line; do
            if [[ "$line" =~ DROP ]]; then
                # Extract IP addresses
                local matches
                matches=$(echo "$line" | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b')
                if [[ -n "$matches" ]]; then
                    for match in $matches; do
                        if [[ ! " ${iptables_bans[@]} " =~ " ${match} " ]]; then
                            iptables_bans+=("$match")
                        fi
                    done
                fi
            fi
        done < <(iptables -L INPUT -n 2>/dev/null)
    fi
    
    # Combine with our internal list
    local all_bans=()
    # Add unique entries from iptables_bans
    for ip in "${iptables_bans[@]}"; do
        if [[ ! " ${all_bans[@]} " =~ " ${ip} " ]]; then
            all_bans+=("$ip")
        fi
    done
    
    # Add unique entries from our internal list
    for ip in "${banned_ips[@]}"; do
        if [[ ! " ${all_bans[@]} " =~ " ${ip} " ]]; then
            all_bans+=("$ip")
        fi
    done
    
    if [ ${#all_bans[@]} -eq 0 ]; then
        echo "No IPs are currently banned"
    else
        echo "Banned IPs:"
        for ip in "${all_bans[@]}"; do
            echo "  $ip"
        done
    fi
}

# Validate IP address format
validate_ip() {
    local ip="$1"
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        local IFS='.'
        local ip_array=($ip)
        for element in "${ip_array[@]}"; do
            if (( element < 0 || element > 255 )); then
                return 1
            fi
        done
        return 0
    else
        return 1
    fi
}

# Main function to demonstrate fban2 functionality
fban2_main() {
    echo "fban2 - Firewall Ban System"
    echo "Available commands:"
    echo "  ban <IP> [reason] - Ban an IP address"
    echo "  unban <IP> - Unban an IP address"
    echo "  status <IP> - Check if IP is banned"
    echo "  list - List all banned IPs"
    echo "  example - Run example usage"
    
    if [ $# -gt 0 ]; then
        local command="$1"
        
        case "$command" in
            ban)
                if [ $# -gt 1 ]; then
                    local ip="$2"
                    local reason="${3:-Manual ban}"
                    ban_ip "$ip" "$reason"
                else
                    echo "Usage: $0 ban <IP> [reason]"
                fi
                ;;
            unban)
                if [ $# -gt 1 ]; then
                    local ip="$2"
                    unban_ip "$ip"
                else
                    echo "Usage: $0 unban <IP>"
                fi
                ;;
            status)
                if [ $# -gt 1 ]; then
                    local ip="$2"
                    check_ip_status "$ip"
                else
                    echo "Usage: $0 status <IP>"
                fi
                ;;
            list)
                list_banned_ips
                ;;
            example)
                echo "Running example usage..."
                echo "Example: ./fban2.sh ban 192.168.1.100 'Suspicious activity'"
                ;;
            *)
                echo "Unknown command: $command"
                echo "Available commands: ban, unban, status, list, example"
                ;;
        esac
    else
        echo
        echo "To use fban2, run with a command:"
        echo "./fban2.sh ban 192.168.1.100 'Reason for ban'"
    fi
}

# Initialize fban2
fban2_init

# Make functions available when sourced
export -f ban_ip
export -f unban_ip
export -f check_ip_status
export -f list_banned_ips
export -f fban2_main