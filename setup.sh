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
    sqlmap \
    prometheus \
    node-exporter \
    bc \
    cron \
    logrotate

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
mkdir -p /var/backups/sarissa
mkdir -p /etc/sarissa/ssl
mkdir -p /opt/sarissa/plugins
chown -R sarissa:sarissa /opt/sarissa
chown -R sarissa:sarissa /var/log/sarissa
chown -R sarissa:sarissa /var/backups/sarissa
chown -R sarissa:sarissa /etc/sarissa

# Set up PostgreSQL
echo -e "${YELLOW}Setting up PostgreSQL...${NC}"
sudo -u postgres psql -c "CREATE USER sarissa WITH PASSWORD 'sarissa_password';"
sudo -u postgres psql -c "CREATE DATABASE sarissa OWNER sarissa;"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE sarissa TO sarissa;"

# Clone and build Sarissa
echo -e "${YELLOW}Building Sarissa...${NC}"
cd /opt/sarissa

# Prompt for repository URL
echo -e "${YELLOW}Please provide the Sarissa repository URL:${NC}"
echo -e "${YELLOW}Example: https://github.com/your-org/sarissa.git${NC}"
read -p "Repository URL: " REPO_URL

if [ -z "$REPO_URL" ]; then
    echo -e "${RED}Repository URL is required${NC}"
    exit 1
fi

# Clone the repository
echo -e "${YELLOW}Cloning repository...${NC}"
git clone "$REPO_URL" .
chown -R sarissa:sarissa .

# Copy configuration files
echo -e "${YELLOW}Setting up configuration...${NC}"
cp config.toml.example config.toml
chown sarissa:sarissa config.toml

# Set up scripts
echo -e "${YELLOW}Setting up utility scripts...${NC}"
chmod +x scripts/*.sh
cp scripts/backup.sh /usr/local/bin/sarissa-backup
cp scripts/health_check.sh /usr/local/bin/sarissa-health-check
cp scripts/maintenance.sh /usr/local/bin/sarissa-maintenance

# Set up log rotation
echo -e "${YELLOW}Setting up log rotation...${NC}"
cp logrotate.d/sarissa /etc/logrotate.d/
chmod 644 /etc/logrotate.d/sarissa

# Set up cron jobs
echo -e "${YELLOW}Setting up scheduled tasks...${NC}"
(crontab -u sarissa -l 2>/dev/null; echo "0 0 * * * /usr/local/bin/sarissa-backup") | crontab -u sarissa -
(crontab -u sarissa -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/sarissa-health-check") | crontab -u sarissa -
(crontab -u sarissa -l 2>/dev/null; echo "0 0 * * 0 /usr/local/bin/sarissa-maintenance clean") | crontab -u sarissa -

# Build the application
echo -e "${YELLOW}Building application...${NC}"
sudo -u sarissa cargo build --release

# Set up systemd service
echo -e "${YELLOW}Setting up systemd service...${NC}"
cp sarissa.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable sarissa
systemctl start sarissa

# Set up Prometheus monitoring
echo -e "${YELLOW}Setting up monitoring...${NC}"
cp prometheus.yml /etc/prometheus/
cp rules/sarissa_alerts.yml /etc/prometheus/rules/
systemctl enable prometheus
systemctl enable node-exporter
systemctl start prometheus
systemctl start node-exporter

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
echo "5. Backup script is installed at /usr/local/bin/sarissa-backup"
echo "6. Health check script is installed at /usr/local/bin/sarissa-health-check"
echo "7. Maintenance script is installed at /usr/local/bin/sarissa-maintenance"
echo "8. Prometheus monitoring is available on port 9090"
echo -e "${YELLOW}Please make sure to:${NC}"
echo "1. Change the default database password"
echo "2. Review and adjust the configuration file"
echo "3. Set up SSL certificates if needed"
echo "4. Configure backup retention settings"
echo "5. Set up monitoring alerts"
echo "6. Review log rotation settings" 