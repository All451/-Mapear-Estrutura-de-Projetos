#!/bin/bash
# Docker Container Exposure Checker
# Script to verify if Docker containers are exposed to the internet

# Global variables to store container information
declare -a container_ids=()
declare -a container_names=()
declare -a container_images=()
declare -a container_ports=()

# Check if Docker is available
check_docker_available() {
    if ! command -v docker &> /dev/null; then
        echo "Docker command not found. Please install Docker first."
        return 1
    fi
    return 0
}

# Get list of running containers with their port mappings
get_running_containers() {
    if ! check_docker_available; then
        return 1
    fi
    
    # Clear existing arrays
    container_ids=()
    container_names=()
    container_images=()
    container_ports=()
    
    # Get running containers
    local container_info
    container_info=$(docker ps --format "table {{.ID}}\t{{.Names}}\t{{.Image}}" 2>/dev/null)
    
    if [ -z "$container_info" ]; then
        echo "No running containers found or Docker is not running."
        return 1
    fi
    
    # Skip the header line and process each container
    echo "$container_info" | tail -n +2 | while IFS=$'\t' read -r id name image; do
        if [ -n "$id" ] && [ -n "$name" ] && [ -n "$image" ]; then
            container_ids+=("${id:0:12}")
            container_names+=("$name")
            container_images+=("$image")
            
            # Get port mappings for this container
            local ports
            ports=$(get_container_port_mappings "$id")
            container_ports+=("$ports")
        fi
    done
}

# Get port mappings for a specific container
get_container_port_mappings() {
    local container_id="$1"
    local port_info
    port_info=$(docker port "$container_id" 2>/dev/null)
    
    if [ -z "$port_info" ]; then
        echo ""
        return
    fi
    
    # Process the port mappings
    local formatted_ports=""
    echo "$port_info" | while IFS= read -r line; do
        if [ -n "$line" ]; then
            # Extract container port and host mapping
            local container_port host_ip host_port
            container_port=$(echo "$line" | cut -d' ' -f1)
            host_mapping=$(echo "$line" | cut -d' ' -f3)
            
            # Split host mapping into IP and port
            if [[ "$host_mapping" == *:* ]]; then
                host_ip=$(echo "$host_mapping" | cut -d':' -f1)
                host_port=$(echo "$host_mapping" | cut -d':' -f2)
            else
                host_ip="0.0.0.0"
                host_port="$host_mapping"
            fi
            
            echo "$container_port->$host_ip:$host_port"
        fi
    done
}

# Check if a specific port is accessible
check_port_accessibility() {
    local host_ip="$1"
    local host_port="$2"
    local accessible_internally=0
    local accessible_externally=0
    local service_info=""
    local risk_level="low"
    
    # Check internal accessibility (localhost)
    if nc -z -w5 127.0.0.1 "$host_port" 2>/dev/null; then
        accessible_internally=1
    fi
    
    # Check external accessibility (if host IP is not localhost or 0.0.0.0)
    if [[ "$host_ip" != "127.0.0.1" ]] && [[ "$host_ip" != "localhost" ]] && [[ "$host_ip" != "0.0.0.0" ]]; then
        if nc -z -w5 "$host_ip" "$host_port" 2>/dev/null; then
            accessible_externally=1
        fi
    fi
    
    # Determine risk level
    if [ $accessible_externally -eq 1 ]; then
        risk_level="high"
    elif [ $accessible_internally -eq 1 ]; then
        risk_level="medium"
    fi
    
    # Try to identify service if accessible
    if [ $accessible_internally -eq 1 ]; then
        service_info=$(identify_service "$host_ip" "$host_port")
    else
        service_info="Unknown service"
    fi
    
    echo "Internal: $accessible_internally, External: $accessible_externally, Risk: $risk_level, Service: $service_info"
}

# Try to identify what service is running on a port
identify_service() {
    local host_ip="$1"
    local host_port="$2"
    
    # Try HTTP/HTTPS
    if curl -s --connect-timeout 5 "http://$host_ip:$host_port" >/dev/null 2>&1; then
        local status_code
        status_code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "http://$host_ip:$host_port" 2>&1)
        echo "HTTP service - Status: $status_code"
        return
    fi
    
    if curl -s --connect-timeout 5 "https://$host_ip:$host_port" >/dev/null 2>&1; then
        local status_code
        status_code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "https://$host_ip:$host_port" 2>&1)
        echo "HTTPS service - Status: $status_code"
        return
    fi
    
    # If HTTP/HTTPS didn't work, just return that something is listening
    echo "Service listening on port"
}

# Scan all running containers for exposed ports
scan_exposed_containers() {
    if ! check_docker_available; then
        return 1
    fi
    
    # Get running containers
    get_running_containers
    
    # Process each container
    for i in "${!container_ids[@]}"; do
        local container_id="${container_ids[$i]}"
        local container_name="${container_names[$i]}"
        local container_image="${container_images[$i]}"
        local ports="${container_ports[$i]}"
        
        if [ -n "$ports" ]; then
            echo "Container: $container_name ($container_id)"
            echo "Image: $container_image"
            echo "Exposed Ports:"
            
            # Process each port mapping
            while IFS= read -r port_mapping; do
                if [ -n "$port_mapping" ]; then
                    local container_port host_ip host_port
                    container_port=$(echo "$port_mapping" | cut -d'-' -f1)
                    host_ip_port=$(echo "$port_mapping" | cut -d'>' -f2)
                    host_ip=$(echo "$host_ip_port" | cut -d':' -f1)
                    host_port=$(echo "$host_ip_port" | cut -d':' -f2)
                    
                    local accessibility_info
                    accessibility_info=$(check_port_accessibility "$host_ip" "$host_port")
                    
                    echo "  - Container Port $container_port -> Host $host_ip:$host_port"
                    echo "    $accessibility_info"
                fi
            done < <(echo "$ports" | tr ' ' '\n')
            echo
        fi
    done
}

# Generate a human-readable report of exposed containers
docker_exposure_check() {
    if ! check_docker_available; then
        echo "Docker not available. Cannot perform exposure check."
        return 1
    fi
    
    local containers_info
    containers_info=$(scan_exposed_containers)
    
    if [ -z "$containers_info" ] || ! echo "$containers_info" | grep -q "Exposed Ports"; then
        echo "No exposed Docker containers found."
        return 0
    fi
    
    echo "Docker Container Exposure Report"
    echo "================================"
    echo
    echo "$containers_info"
}

# Get security recommendations based on findings
get_security_recommendations() {
    if ! check_docker_available; then
        echo "Docker not available. Cannot generate recommendations."
        return 1
    fi
    
    local containers_info
    containers_info=$(scan_exposed_containers)
    
    if [ -z "$containers_info" ] || ! echo "$containers_info" | grep -q "Exposed Ports"; then
        echo "No exposed containers found - good security posture!"
        return 0
    fi
    
    echo "Security Recommendations:"
    echo "- Review exposed ports and consider if they need to be accessible"
    echo "- Use Docker networks to isolate containers when possible"
    echo "- Implement proper firewall rules to restrict access"
    echo "- Regularly audit container configurations"
    echo "- Consider using 'docker run --publish 127.0.0.1:PORT:PORT' to bind to localhost only"
    
    # Count high-risk exposures
    local high_risk_count=0
    while IFS= read -r line; do
        if [[ "$line" =~ "Risk: high" ]]; then
            ((high_risk_count++))
        fi
    done < <(echo "$containers_info")
    
    if [ $high_risk_count -gt 0 ]; then
        echo "- CRITICAL: $high_risk_count high-risk exposures detected - immediate action recommended"
    fi
}

# Make functions available when sourced
export -f docker_exposure_check
export -f get_security_recommendations