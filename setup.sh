#!/bin/bash

# Exit on error
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}Starting Sarissa installation...${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root${NC}"
    exit 1
fi

# Install system dependencies
echo -e "${YELLOW}Installing system dependencies...${NC}"
apt-get update
apt-get install -y \
    curl \
    build-essential \
    pkg-config \
    libssl-dev \
    libpq-dev \
    clang \
    git \
    postgresql \
    postgresql-contrib \
    ca-certificates \
    nmap \
    sqlmap

# Install Rust
echo -e "${YELLOW}Installing Rust...${NC}"
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env

# Create Sarissa user and group
echo -e "${YELLOW}Creating Sarissa user and group...${NC}"
if ! getent group sarissa >/dev/null; then
    groupadd sarissa
fi

if ! getent passwd sarissa >/dev/null; then
    useradd -m -g sarissa -s /bin/bash sarissa
fi

# Create necessary directories
echo -e "${YELLOW}Creating necessary directories...${NC}"
mkdir -p /opt/sarissa
mkdir -p /var/log/sarissa
chown -R sarissa:sarissa /opt/sarissa
chown -R sarissa:sarissa /var/log/sarissa

# Set up PostgreSQL
echo -e "${YELLOW}Setting up PostgreSQL...${NC}"
sudo -u postgres psql -c "CREATE USER sarissa WITH PASSWORD 'sarissa_password';"
sudo -u postgres psql -c "CREATE DATABASE sarissa OWNER sarissa;"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE sarissa TO sarissa;"

# Clone and build Sarissa
echo -e "${YELLOW}Building Sarissa...${NC}"
cd /opt/sarissa
git clone https://github.com/your-org/sarissa.git .
chown -R sarissa:sarissa .
sudo -u sarissa cargo build --release

# Copy configuration files
echo -e "${YELLOW}Setting up configuration...${NC}"
cp config.toml.example config.toml
chown sarissa:sarissa config.toml

# Set up systemd service
echo -e "${YELLOW}Setting up systemd service...${NC}"
cp sarissa.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable sarissa
systemctl start sarissa

# Check service status
echo -e "${YELLOW}Checking service status...${NC}"
if systemctl is-active --quiet sarissa; then
    echo -e "${GREEN}Sarissa service is running successfully!${NC}"
else
    echo -e "${RED}Sarissa service failed to start. Check logs with: journalctl -u sarissa${NC}"
    exit 1
fi

echo -e "${GREEN}Installation completed successfully!${NC}"
echo -e "${YELLOW}Important information:${NC}"
echo "1. Sarissa is running on ports 8080 and 8081"
echo "2. Logs are available in /var/log/sarissa/"
echo "3. Configuration file is at /opt/sarissa/config.toml"
echo "4. Database credentials are in the configuration file"
echo -e "${YELLOW}Please make sure to:${NC}"
echo "1. Change the default database password"
echo "2. Review and adjust the configuration file"
echo "3. Set up SSL certificates if needed" 