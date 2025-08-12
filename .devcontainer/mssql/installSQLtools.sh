#!/bin/bash
set -euo pipefail

echo "Installing mssql-tools"

# Install prerequisites
apt-get update
apt-get -y install --no-install-recommends curl gpg lsb-release unzip

# Add Microsoft GPG key and repository
curl -sSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg
chmod 644 /usr/share/keyrings/microsoft-prod.gpg

DISTRO=$(lsb_release -is | tr '[:upper:]' '[:lower:]')
CODENAME=$(lsb_release -cs)
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/repos/microsoft-${DISTRO}-${CODENAME}-prod ${CODENAME} main" > /etc/apt/sources.list.d/microsoft.list

# Update package list and install SQL tools
apt-get update
ACCEPT_EULA=Y apt-get -y install --no-install-recommends unixodbc-dev msodbcsql17 libunwind8 mssql-tools

echo "Installing sqlpackage"
curl -sSL -o sqlpackage.zip "https://aka.ms/sqlpackage-linux"
mkdir -p /opt/sqlpackage
unzip sqlpackage.zip -d /opt/sqlpackage
rm sqlpackage.zip
chmod a+x /opt/sqlpackage/sqlpackage

echo "SQL tools installation completed successfully"
