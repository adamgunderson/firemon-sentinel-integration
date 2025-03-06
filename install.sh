#!/bin/bash
# install.sh
# Installs the FireMon syslog-ng integration

set -e

# Create necessary directories
echo "Creating directories..."
mkdir -p /etc/syslog-ng/conf.d
mkdir -p /etc/firemon
mkdir -p /usr/local/bin
mkdir -p /var/log/firemon

# Copy configuration files
echo "Installing configuration files..."
cp firemon_alerts.conf /etc/syslog-ng/conf.d/
cp api_fetch.conf /etc/firemon/

# Copy Python scripts
echo "Installing Python scripts..."
cp firemon_api_fetch.py /usr/local/bin/
cp sentinel_integration.py /usr/local/bin/

# Set permissions
echo "Setting permissions..."
chmod +x /usr/local/bin/firemon_api_fetch.py
chmod +x /usr/local/bin/sentinel_integration.py

# Install Python dependencies
echo "Installing Python dependencies..."
pip3 install requests configparser

# Restart syslog-ng
echo "Restarting syslog-ng..."
if systemctl is-active --quiet syslog-ng; then
    systemctl restart syslog-ng
else
    echo "Warning: syslog-ng service not running. Please start it manually."
fi

echo "Installation complete!"
echo "Next steps:"
echo "1. Edit /etc/firemon/api_fetch.conf with your credentials"
echo "2. Verify the syslog-ng configuration matches your environment"
echo "3. Test with a sample FireMon message"