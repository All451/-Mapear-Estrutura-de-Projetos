#!/bin/bash
# Main script to run the security suite

# Make sure all modules have executable permissions
chmod +x /workspace/*.sh

# Run the main security suite
exec /workspace/security_suite.sh "$@"