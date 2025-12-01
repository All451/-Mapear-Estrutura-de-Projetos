#!/bin/bash
# Cybersecurity Suite - A Comprehensive Cybersecurity Tool
# This script integrates multiple security modules for comprehensive system analysis and protection.

# Source the individual security modules
source ./cybersecurity_module.sh
source ./ufw_port_checker.sh
source ./fban2.sh
source ./docker_exposure_checker.sh

# Main Cybersecurity Suite class equivalent
run_comprehensive_scan() {
    echo "============================================================"
    echo "CYBERSECURITY COMPREHENSIVE SCAN"
    echo "============================================================"
    
    # 1. System integrity check
    echo
    echo "[1/6] Running System Integrity Check..."
    system_integrity_scan
    
    # 2. Network security check
    echo
    echo "[2/6] Running Network Security Check..."
    network_security_scan
    
    # 3. Firewall analysis
    echo
    echo "[3/6] Running Firewall Analysis..."
    firewall_analysis
    
    # 4. Docker container exposure check
    echo
    echo "[4/6] Running Docker Container Exposure Check..."
    docker_exposure_scan
    
    # 5. File system security check
    echo
    echo "[5/6] Running File System Security Check..."
    file_system_security_scan
    
    # 6. Active ban status
    echo
    echo "[6/6] Checking Active Firewall Bans..."
    ban_status_check
    
    # Generate final report
    generate_comprehensive_report
}

system_integrity_scan() {
    echo "  - Checking system for common security issues..."
    security_audit
    
    echo "  - Checking system integrity..."
    check_system_integrity
    
    # Additional checks
    check_running_processes
    check_system_logs
}

check_running_processes() {
    echo "  - Checking for suspicious running processes..."
    if command -v ps &> /dev/null; then
        # Look for common suspicious processes
        suspicious_processes=$(ps aux | grep -E "(minerd|xmr|crypto|stratum)" | grep -v grep | head -5)
        if [ -n "$suspicious_processes" ]; then
            echo "  - Found potentially suspicious processes:"
            echo "$suspicious_processes" | while read -r proc; do
                echo "    $proc"
            done
        else
            echo "  - No suspicious processes detected"
        fi
    else
        echo "  - ps command not available"
    fi
}

check_system_logs() {
    echo "  - Checking system logs for security events..."
    
    log_files=("/var/log/auth.log" "/var/log/secure" "/var/log/syslog" "/var/log/messages")
    found_events=0
    
    for log_file in "${log_files[@]}"; do
        if [ -f "$log_file" ]; then
            # Check last 50 lines for authentication failures
            recent_events=$(tail -50 "$log_file" 2>/dev/null | grep -i -E "(failed|invalid|authentication failure)" | head -5)
            if [ -n "$recent_events" ]; then
                event_count=$(echo "$recent_events" | wc -l)
                found_events=$((found_events + event_count))
                echo "  - Found $event_count suspicious authentication events in $log_file"
            fi
        fi
    done
    
    if [ $found_events -eq 0 ]; then
        echo "  - No suspicious authentication events found in recent logs"
    fi
}

network_security_scan() {
    # Check open ports
    echo "  - Checking open ports via UFW..."
    local ports_output
    ports_output=$(list_open_ports)
    
    # Count open ports by looking for the Port lines
    local port_count=0
    echo "$ports_output" | while read -r line; do
        if [[ "$line" =~ ^[[:space:]]*Port:[[:space:]] ]]; then
            ((port_count++))
        fi
    done
    
    echo "  - Found ports via UFW (see details below):"
    echo "$ports_output"
    
    # Check for common vulnerable ports
    local vulnerable_ports=("21" "23" "135" "139" "445" "3389")
    local open_vulnerable=()
    
    for port_info in $(echo "$ports_output" | grep -oE "Port: [0-9:]+"); do
        port_num=$(echo "$port_info" | cut -d' ' -f2 | cut -d':' -f1)
        for vulnerable_port in "${vulnerable_ports[@]}"; do
            if [ "$port_num" = "$vulnerable_port" ]; then
                open_vulnerable+=("$port_num")
            fi
        done
    done
    
    if [ ${#open_vulnerable[@]} -gt 0 ]; then
        echo "  - WARNING: ${#open_vulnerable[@]} potentially vulnerable ports are open: ${open_vulnerable[*]}"
    else
        echo "  - No commonly vulnerable ports detected"
    fi
}

firewall_analysis() {
    echo "  - UFW Status:"
    local ufw_status
    ufw_status=$(check_ufw_status)
    echo "$ufw_status" | while read -r line; do
        echo "    $line"
    done
}

docker_exposure_scan() {
    echo "  - Checking Docker container exposure..."
    if command -v docker &> /dev/null; then
        docker_exposure_check
    else
        echo "  - Docker command not found. Docker security checks skipped."
    fi
}

file_system_security_scan() {
    echo "  - Scanning for sensitive files..."
    
    # Look for sensitive files in current directory
    local sensitive_files=()
    while IFS= read -r -d '' file; do
        sensitive_files+=("$file")
    done < <(find . -type f -name "*.env" -o -name "*config*" -o -name "*password*" -o -name "*secret*" -o -name "*.key" -o -name "*.pem" -o -name "id_rsa*" -o -name "*.token" -print0 2>/dev/null)
    
    if [ ${#sensitive_files[@]} -gt 0 ]; then
        echo "  - Found ${#sensitive_files[@]} potentially sensitive files:"
        for file in "${sensitive_files[@]:0:10}"; do  # Limit output to first 10
            echo "    $file"
        done
        if [ ${#sensitive_files[@]} -gt 10 ]; then
            echo "    ... and $((${#sensitive_files[@]} - 10)) more"
        fi
    else
        echo "  - No sensitive files detected in current directory"
    fi
}

ban_status_check() {
    echo "  - Checking active firewall bans..."
    local banned_count=0
    banned_count=$(list_banned_ips | grep -c "^[0-9]" 2>/dev/null || echo 0)
    echo "  - Total banned IPs: $banned_count"
    
    list_banned_ips | while read -r line; do
        if [[ "$line" =~ ^[[:space:]]*[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3} ]]; then
            echo "    $line"
        fi
    done
}

generate_comprehensive_report() {
    echo
    echo "============================================================"
    echo "COMPREHENSIVE SECURITY REPORT"
    echo "============================================================"
    
    # Summary of findings
    echo
    echo "SUMMARY:"
    echo "  - System integrity: CHECKED"
    echo "  - Network security: CHECKED"
    echo "  - Firewall status: CHECKED"
    echo "  - Docker exposure: CHECKED"
    echo "  - File system security: CHECKED"
    echo "  - Active bans: CHECKED"
    
    echo
    echo "RECOMMENDATIONS:"
    echo "  - Review all open ports and close unnecessary ones"
    echo "  - Regularly update system packages"
    echo "  - Monitor system logs for suspicious activity"
    echo "  - Implement strong password policies"
    echo "  - Use fail2ban or similar tools for automatic blocking"
    echo "  - Regular security audits"
}

interactive_mode() {
    while true; do
        echo
        echo "=================================================="
        echo "CYBERSECURITY SUITE - INTERACTIVE MODE"
        echo "=================================================="
        echo "1. Run Comprehensive Security Scan"
        echo "2. Network Security Analysis"
        echo "3. Firewall Management"
        echo "4. Docker Container Security"
        echo "5. File System Security"
        echo "6. Exit"
        
        read -p "Select an option (1-6): " choice
        
        case $choice in
            1)
                run_comprehensive_scan
                ;;
            2)
                network_security_menu
                ;;
            3)
                firewall_management_menu
                ;;
            4)
                docker_security_menu
                ;;
            5)
                file_system_security_menu
                ;;
            6)
                echo "Exiting Cybersecurity Suite. Stay secure!"
                exit 0
                ;;
            *)
                echo "Invalid option. Please select 1-6."
                ;;
        esac
        
        read -p "Press Enter to continue..."
    done
}

network_security_menu() {
    echo
    echo "--- NETWORK SECURITY ANALYSIS ---"
    echo "Current UFW Status:"
    check_ufw_status
    echo
    echo "Open ports:"
    list_open_ports
}

firewall_management_menu() {
    echo
    echo "--- FIREWALL MANAGEMENT ---"
    
    while true; do
        echo
        echo "Firewall Management Options:"
        echo "  1. Ban an IP address"
        echo "  2. Unban an IP address"
        echo "  3. Check IP status"
        echo "  4. List banned IPs"
        echo "  5. Back to main menu"
        
        read -p "Select an option (1-5): " choice
        
        case $choice in
            1)
                read -p "Enter IP address to ban: " ip
                read -p "Enter reason for ban (optional): " reason
                if [ -z "$reason" ]; then
                    reason="Manual ban"
                fi
                ban_ip "$ip" "$reason"
                ;;
            2)
                read -p "Enter IP address to unban: " ip
                unban_ip "$ip"
                ;;
            3)
                read -p "Enter IP address to check: " ip
                check_ip_status "$ip"
                ;;
            4)
                list_banned_ips
                ;;
            5)
                break
                ;;
            *)
                echo "Invalid option. Please select 1-5."
                ;;
        esac
    done
}

docker_security_menu() {
    echo
    echo "--- DOCKER CONTAINER SECURITY ---"
    if command -v docker &> /dev/null; then
        docker_exposure_check
        echo
        get_security_recommendations
    else
        echo "Docker command not found. Please install Docker first."
    fi
}

file_system_security_menu() {
    echo
    echo "--- FILE SYSTEM SECURITY ---"
    echo "Checking for sensitive files in current directory..."
    
    # Look for sensitive files
    local sensitive_files=()
    while IFS= read -r -d '' file; do
        sensitive_files+=("$file")
    done < <(find . -type f -name "*.env" -o -name "*config*" -o -name "*password*" -o -name "*secret*" -o -name "*.key" -o -name "*.pem" -o -name "id_rsa*" -o -name "*.token" -print0 2>/dev/null)
    
    if [ ${#sensitive_files[@]} -gt 0 ]; then
        echo "Found ${#sensitive_files[@]} potentially sensitive files:"
        for file in "${sensitive_files[@]}"; do
            echo "  $file"
        done
    else
        echo "No sensitive files detected in current directory"
    fi
}

show_help() {
    echo "Cybersecurity Suite - A Comprehensive Cybersecurity Tool"
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  --scan      Run comprehensive security scan"
    echo "  -i, --interactive  Run in interactive mode"
    echo "  -v, --version      Show version information"
    echo "  -h, --help         Show this help message"
    echo
    echo "Examples:"
    echo "  $0                    # Run interactive mode"
    echo "  $0 --scan            # Run comprehensive scan"
    echo "  $0 --interactive     # Run interactive mode"
    echo "  $0 -i                # Run interactive mode"
}

show_version() {
    echo "Cybersecurity Suite v1.0"
    echo "A comprehensive tool for system security analysis and protection"
}

# Main function
main() {
    if [ $# -eq 0 ]; then
        # Default to interactive mode
        echo "Welcome to the Cybersecurity Suite!"
        echo "Use --help for available options"
        interactive_mode
    else
        case "$1" in
            --scan)
                run_comprehensive_scan
                ;;
            -i|--interactive)
                interactive_mode
                ;;
            -v|--version)
                show_version
                ;;
            -h|--help)
                show_help
                ;;
            *)
                echo "Unknown option: $1"
                echo "Use --help for available options"
                exit 1
                ;;
        esac
    fi
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi