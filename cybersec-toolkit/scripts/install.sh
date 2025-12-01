#!/bin/bash
# Installation script for the Cybersecurity Toolkit

set -e  # Exit on any error

echo "Installing Cybersecurity Toolkit..."

# Check if running as root (for system-wide installation)
if [ "$EUID" -eq 0 ]; then
    INSTALL_PREFIX="/usr/local"
    CONFIG_DIR="/etc/cybersec"
    echo "Installing system-wide to $INSTALL_PREFIX"
else
    INSTALL_PREFIX="$HOME/.local"
    CONFIG_DIR="$HOME/.cybersec"
    echo "Installing user-only to $INSTALL_PREFIX"
fi

# Create necessary directories
mkdir -p "$INSTALL_PREFIX/bin"
mkdir -p "$CONFIG_DIR"

# Copy the main script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cp "$SCRIPT_DIR/bin/cybersec.sh" "$INSTALL_PREFIX/bin/cybersec"

# Make executable
chmod +x "$INSTALL_PREFIX/bin/cybersec"

# Install Python dependencies
if command -v pip &> /dev/null; then
    echo "Installing Python dependencies..."
    pip install -r "$SCRIPT_DIR/requirements.txt"
else
    echo "Error: pip is not available. Please install Python pip first."
    exit 1
fi

# Install the Python package
if command -v python3 &> /dev/null; then
    echo "Installing Python package..."
    python3 "$SCRIPT_DIR/setup.py" install --user
else
    echo "Error: python3 is not available. Please install Python 3 first."
    exit 1
fi

# Copy example config if it doesn't exist
if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
    echo "Creating default configuration..."
    cp "$SCRIPT_DIR/config/cybersec.yaml.example" "$CONFIG_DIR/config.yaml"
fi

echo "Installation completed!"
echo "You can now run 'cybersec --help' to get started."
echo "Configuration is located at: $CONFIG_DIR/config.yaml"