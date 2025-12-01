#!/bin/bash
# Wrapper script for the Cybersecurity Toolkit

# Set the Python interpreter
PYTHON_CMD="python3"

# Find the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Add the project root to Python path
export PYTHONPATH="$PROJECT_ROOT:$PYTHONPATH"

# Run the main CLI application
exec $PYTHON_CMD -m cybersec.cli.main "$@"