#!/bin/bash
# Run Script for Cybersecurity Toolkit

echo "🛡️  CYBERSECURITY TOOLKIT v1.0 🛡️"
echo "A comprehensive tool for system security analysis and protection"
echo

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "Python3 is not installed. Please install Python3 first."
    exit 1
fi

# Run the main cybersecurity toolkit
python3 /workspace/cybersec_toolkit.py "$@"