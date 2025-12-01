#!/bin/bash
# Security Suite - Main Module
# This script integrates all security modules: cybersecurity, UFW port checker, and fban2.

# Source the individual security modules
source ./cybersecurity_module.sh
source ./ufw_port_checker.sh
source ./fban2.sh
source ./docker_exposure_checker.sh

# Display the main menu for the security suite
display_menu() {
    echo
    echo "=================================================="
    echo "CYBERSECURITY SUITE"
    echo "=================================================="
    echo "1. General Security Audit"
    echo "2. UFW Port Verification"
    echo "3. Firewall Ban Management (fban2)"
    echo "4. Docker Container Exposure Check"
    echo "5. Run Complete Security Scan"
    echo "6. Exit"
    echo "=================================================="
}

# Run general security audit
run_security_audit() {
    echo
    echo "--- GENERAL SECURITY AUDIT ---"
    security_audit
    check_system_integrity
    echo "Security audit completed."
}

# Run UFW port verification
run_ufw_check() {
    echo
    echo "--- UFW PORT VERIFICATION ---"
    echo "Current UFW Status:"
    check_ufw_status
    
    echo
    echo "Open ports:"
    list_open_ports
}

# Run firewall ban management interface
run_fban_management() {
    echo
    echo "--- FIREWALL BAN MANAGEMENT (fban2) ---"
    
    while true; do
        echo
        echo "fban2 Options:"
        echo "  1. Ban an IP address"
        echo "  2. Unban an IP address"
        echo "  3. Check IP status"
        echo "  4. List banned IPs"
        echo "  5. Go back to main menu"
        
        read -p "Select an option (1-5): " choice
        
        case $choice in
            1)
                read -p "Enter IP address to ban: " ip
                read -p "Enter reason for ban (optional): " reason
                if [ -z "$reason" ]; then
                    reason="No reason provided"
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

# Run Docker container exposure check
run_docker_exposure_check() {
    echo
    echo "--- DOCKER CONTAINER EXPOSURE CHECK ---"
    docker_exposure_check
    echo
    get_security_recommendations
}

# Run a complete security scan using all modules
run_complete_scan() {
    echo
    echo "--- COMPLETE SECURITY SCAN ---"
    
    echo "Running general security audit..."
    security_audit
    check_system_integrity
    
    echo
    echo "Checking firewall and ports..."
    echo "UFW Status:"
    check_ufw_status
    
    echo
    echo "Open ports:"
    list_open_ports
    
    echo
    echo "Checking Docker containers..."
    docker_exposure_check
    
    echo
    echo "Checking active bans..."
    list_banned_ips
    echo "Complete security scan finished."
}

# Main function to run the security suite
main() {
    echo "Welcome to the Cybersecurity Suite!"
    
    while true; do
        display_menu
        read -p "Select an option (1-6): " choice
        
        case $choice in
            1)
                run_security_audit
                ;;
            2)
                run_ufw_check
                ;;
            3)
                run_fban_management
                ;;
            4)
                run_docker_exposure_check
                ;;
            5)
                run_complete_scan
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

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main
fi