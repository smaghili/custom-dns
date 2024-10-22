#!/bin/bash

# Installation script for DNS service
INSTALL_DIR="/opt/dns"
REPO_URL="https://github.com/yourusername/dns-server.git"  # Replace with your actual repo URL
BIN_PATH="/usr/local/bin/dns"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# Install required packages
echo "Installing required packages..."
apt-get update
apt-get install -y python3 python3-pip git

# Install Python dependencies
pip3 install requests dnslib

# Create installation directory
echo "Creating installation directory..."
mkdir -p $INSTALL_DIR

# Clone or update repository
if [ -d "$INSTALL_DIR/.git" ]; then
    echo "Updating existing installation..."
    cd $INSTALL_DIR
    git pull
else
    echo "Performing fresh installation..."
    git clone $REPO_URL $INSTALL_DIR
fi

# Create symlink to main script
echo "Creating command symlink..."
ln -sf $INSTALL_DIR/dns.py $BIN_PATH
chmod +x $INSTALL_DIR/dns.py

echo "Installation complete!"
echo "You can now use the 'dns' command to start the service."
