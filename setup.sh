#!/bin/bash

# Exit on error
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Version requirements
REQUIRED_POSTGRESQL_VERSION="12"
REQUIRED_NODE_EXPORTER_VERSION="1.7.0"
REQUIRED_PROMETHEUS_VERSION="2.45.0"

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to get version number
get_version() {
    local version
    version=$("$1" --version 2>&1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
    echo "$version"
}

# Function to compare versions
version_gt() {
    test "$(printf '%s\n' "$@" | sort -V | head -n1)" != "$1"
}

# Function to handle errors
handle_error() {
    echo -e "${RED}Error: $1${NC}"
    if [ -n "$2" ]; then
        echo -e "${YELLOW}Attempting fallback: $2${NC}"
        eval "$2"
    else
        exit 1
    fi
}

echo -e "${GREEN}Starting Sarissa installation...${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root${NC}"
    exit 1
fi

# Install system dependencies
echo -e "${YELLOW}Installing system dependencies...${NC}"
if ! apt-get update; then
    handle_error "Failed to update package lists" "apt-get update --allow-releaseinfo-change"
fi

# Install basic dependencies
echo -e "${YELLOW}Installing basic dependencies...${NC}"
DEPS="curl build-essential pkg-config libssl-dev libpq-dev clang git ca-certificates nmap sqlmap bc cron logrotate"
if ! apt-get install -y $DEPS; then
    handle_error "Failed to install basic dependencies" "apt-get install -y --no-install-recommends $DEPS"
fi

# Install PostgreSQL
echo -e "${YELLOW}Installing PostgreSQL...${NC}"
if ! apt-get install -y postgresql postgresql-contrib; then
    handle_error "Failed to install PostgreSQL" "apt-get install -y postgresql-common && apt-get install -y postgresql postgresql-contrib"
fi

# Get PostgreSQL version and data directory
PG_VERSION=$(pg_config --version | grep -oE '[0-9]+' | head -1)
PG_DATA_DIR="/var/lib/postgresql/${PG_VERSION}/main"

echo -e "${YELLOW}PostgreSQL version: ${PG_VERSION}${NC}"
echo -e "${YELLOW}PostgreSQL data directory: ${PG_DATA_DIR}${NC}"

# Check PostgreSQL service status
echo -e "${YELLOW}Checking PostgreSQL service status...${NC}"
systemctl status postgresql

# Check PostgreSQL process
echo -e "${YELLOW}Checking PostgreSQL processes...${NC}"
ps aux | grep postgres

# Check PostgreSQL logs
echo -e "${YELLOW}Checking PostgreSQL logs...${NC}"
tail -n 50 /var/log/postgresql/postgresql-${PG_VERSION}-main.log

# Initialize PostgreSQL if not already initialized
if [ ! -d "$PG_DATA_DIR" ]; then
    echo -e "${YELLOW}Initializing PostgreSQL database...${NC}"
    if ! sudo -u postgres /usr/lib/postgresql/${PG_VERSION}/bin/initdb -D "$PG_DATA_DIR"; then
        echo -e "${RED}Failed to initialize PostgreSQL database. Checking logs...${NC}"
        tail -n 50 /var/log/postgresql/postgresql-${PG_VERSION}-main.log
        handle_error "Failed to initialize PostgreSQL database"
    fi
fi

# Ensure PostgreSQL data directory exists and has correct permissions
if [ ! -d "$PG_DATA_DIR" ]; then
    echo -e "${RED}PostgreSQL data directory not found. Creating...${NC}"
    if ! mkdir -p "$PG_DATA_DIR"; then
        handle_error "Failed to create PostgreSQL data directory"
    fi
    if ! chown postgres:postgres "$PG_DATA_DIR"; then
        handle_error "Failed to set PostgreSQL data directory permissions"
    fi
fi

# Check directory permissions
echo -e "${YELLOW}Checking PostgreSQL directory permissions...${NC}"
ls -la "$PG_DATA_DIR"

# Start and enable PostgreSQL
echo -e "${YELLOW}Starting PostgreSQL service...${NC}"
if ! systemctl enable postgresql; then
    echo -e "${RED}Failed to enable PostgreSQL service. Checking status...${NC}"
    systemctl status postgresql
    handle_error "Failed to enable PostgreSQL service" "systemctl unmask postgresql && systemctl enable postgresql"
fi

# Stop PostgreSQL if it's running
echo -e "${YELLOW}Stopping PostgreSQL service...${NC}"
systemctl stop postgresql

# Start PostgreSQL
echo -e "${YELLOW}Starting PostgreSQL service...${NC}"
if ! systemctl start postgresql; then
    echo -e "${RED}Failed to start PostgreSQL service. Checking logs...${NC}"
    journalctl -u postgresql -n 50
    handle_error "Failed to start PostgreSQL service" "systemctl restart postgresql"
fi

# Wait for PostgreSQL to be ready
echo -e "${YELLOW}Waiting for PostgreSQL to be ready...${NC}"
for i in {1..30}; do
    if pg_isready -h localhost -p 5432 -U postgres >/dev/null 2>&1; then
        echo -e "${GREEN}PostgreSQL is ready${NC}"
        break
    fi
    if [ $i -eq 30 ]; then
        echo -e "${RED}PostgreSQL failed to start within 30 seconds. Checking logs...${NC}"
        journalctl -u postgresql -n 50
        handle_error "PostgreSQL failed to start within 30 seconds" \
            "systemctl restart postgresql && sleep 5 && pg_isready -h localhost -p 5432 -U postgres"
    fi
    echo -e "${YELLOW}Waiting for PostgreSQL to start... (${i}/30)${NC}"
    sleep 1
done

# Verify PostgreSQL socket exists
if [ ! -S /var/run/postgresql/.s.PGSQL.5432 ]; then
    echo -e "${RED}PostgreSQL socket not found. Checking socket directory...${NC}"
    ls -la /var/run/postgresql/
    handle_error "PostgreSQL socket not found" \
        "systemctl restart postgresql && sleep 5 && [ -S /var/run/postgresql/.s.PGSQL.5432 ]"
fi

# Check PostgreSQL connection
echo -e "${YELLOW}Testing PostgreSQL connection...${NC}"
if ! sudo -u postgres psql -c "SELECT version();"; then
    echo -e "${RED}Failed to connect to PostgreSQL. Checking connection details...${NC}"
    echo "PostgreSQL version: $(pg_config --version)"
    echo "PostgreSQL data directory: $PG_DATA_DIR"
    echo "PostgreSQL socket: /var/run/postgresql/.s.PGSQL.5432"
    handle_error "Failed to connect to PostgreSQL"
fi

# Set up PostgreSQL
echo -e "${YELLOW}Setting up PostgreSQL...${NC}"
# Ensure PostgreSQL service is running
if ! systemctl is-active --quiet postgresql; then
    echo -e "${YELLOW}Starting PostgreSQL service...${NC}"
    systemctl start postgresql
    # Wait for PostgreSQL to be ready
    for i in {1..30}; do
        if pg_isready -h localhost -p 5432 -U postgres >/dev/null 2>&1; then
            echo -e "${GREEN}PostgreSQL is ready${NC}"
            break
        fi
        if [ $i -eq 30 ]; then
            handle_error "PostgreSQL failed to start within 30 seconds" \
                "systemctl restart postgresql && sleep 5 && pg_isready -h localhost -p 5432 -U postgres"
        fi
        echo -e "${YELLOW}Waiting for PostgreSQL to start... (${i}/30)${NC}"
        sleep 1
    done
else
    echo -e "${GREEN}PostgreSQL service is already running.${NC}"
fi

# Create user if it doesn't exist
if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='sarissa'" | grep -q 1; then
    sudo -u postgres psql -c "CREATE USER sarissa WITH PASSWORD 'sarissa_password';"
else
    echo -e "${YELLOW}PostgreSQL user 'sarissa' already exists. Skipping creation.${NC}"
fi
# Create database if it doesn't exist
sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname = 'sarissa'" | grep -q 1 || sudo -u postgres psql -c "CREATE DATABASE sarissa OWNER sarissa;"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE sarissa TO sarissa;"

# Configure PostgreSQL to accept local connections
echo -e "${YELLOW}Configuring PostgreSQL...${NC}"
PG_HBA_CONF=$(sudo -u postgres psql -t -P format=unaligned -c "SHOW hba_file;")
for rule in \
    "local   all             sarissa                                  md5" \
    "host    all             sarissa          127.0.0.1/32            md5" \
    "host    all             sarissa          ::1/128                 md5"
do
    if ! echo "$rule" | sudo -u postgres tee -a "$PG_HBA_CONF"; then
        handle_error "Failed to add PostgreSQL rule: $rule"
    fi
done

# Reload PostgreSQL configuration
if ! systemctl reload postgresql; then
    handle_error "Failed to reload PostgreSQL configuration" "systemctl restart postgresql"
fi

# Verify PostgreSQL is running and accessible
if ! pg_isready -h localhost -p 5432 -U postgres >/dev/null 2>&1; then
    handle_error "PostgreSQL is not running or not accessible" "systemctl restart postgresql && sleep 5 && pg_isready -h localhost -p 5432 -U postgres"
fi

# Check for collation version mismatch
echo -e "${YELLOW}Checking for collation version mismatch...${NC}"
if sudo -u postgres psql -c "ALTER DATABASE template1 REFRESH COLLATION VERSION;" 2>&1 | grep -q "collation version mismatch"; then
    echo -e "${YELLOW}Collation version mismatch detected. Attempting to fix...${NC}"
    sudo -u postgres psql -c "ALTER DATABASE template1 REFRESH COLLATION VERSION;"
    if [ $? -ne 0 ]; then
        handle_error "Failed to fix collation version mismatch" "sudo -u postgres psql -c 'ALTER DATABASE template1 REFRESH COLLATION VERSION;'"
    fi
else
    echo -e "${GREEN}No collation version mismatch detected.${NC}"
fi

# Install Prometheus
echo -e "${YELLOW}Installing Prometheus...${NC}"
# Add Prometheus repository
if ! curl -fsSL https://apt.grafana.com/gpg.key | gpg --dearmor -o /usr/share/keyrings/grafana-archive-keyring.gpg; then
    handle_error "Failed to add Grafana GPG key" "curl -fsSL https://packages.grafana.com/gpg.key | gpg --dearmor -o /usr/share/keyrings/grafana-archive-keyring.gpg"
fi

if ! echo "deb [signed-by=/usr/share/keyrings/grafana-archive-keyring.gpg] https://apt.grafana.com stable main" | tee /etc/apt/sources.list.d/grafana.list; then
    handle_error "Failed to add Grafana repository"
fi

# Update and install Prometheus
if ! apt-get update; then
    handle_error "Failed to update package lists after adding repository" "apt-get update --allow-releaseinfo-change"
fi

if ! apt-get install -y prometheus; then
    handle_error "Failed to install Prometheus" "apt-get install -y prometheus --no-install-recommends"
fi

# Verify Prometheus version
if command_exists prometheus; then
    PROM_VERSION=$(get_version prometheus)
    if version_gt "$REQUIRED_PROMETHEUS_VERSION" "$PROM_VERSION"; then
        handle_error "Prometheus version $PROM_VERSION is too old. Required: $REQUIRED_PROMETHEUS_VERSION" \
            "curl -L https://github.com/prometheus/prometheus/releases/download/v$REQUIRED_PROMETHEUS_VERSION/prometheus-$REQUIRED_PROMETHEUS_VERSION.linux-amd64.tar.gz -o /tmp/prometheus.tar.gz && \
             tar xvfz /tmp/prometheus.tar.gz -C /tmp && \
             mv /tmp/prometheus-$REQUIRED_PROMETHEUS_VERSION.linux-amd64/prometheus /usr/local/bin/ && \
             rm -rf /tmp/prometheus*"
    fi
fi

# Install Node Exporter
echo -e "${YELLOW}Installing Node Exporter...${NC}"
NODE_EXPORTER_VERSION="$REQUIRED_NODE_EXPORTER_VERSION"
NODE_EXPORTER_ARCH="amd64"
NODE_EXPORTER_URL="https://github.com/prometheus/node_exporter/releases/download/v${NODE_EXPORTER_VERSION}/node_exporter-${NODE_EXPORTER_VERSION}.linux-${NODE_EXPORTER_ARCH}.tar.gz"

# Create temporary directory for Node Exporter
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

# Try to download Node Exporter
if ! curl -L "$NODE_EXPORTER_URL" -o node_exporter.tar.gz; then
    handle_error "Failed to download Node Exporter" \
        "curl -L https://github.com/prometheus/node_exporter/releases/latest/download/node_exporter-${NODE_EXPORTER_VERSION}.linux-${NODE_EXPORTER_ARCH}.tar.gz -o node_exporter.tar.gz"
fi

# Extract and install Node Exporter
if ! tar xvfz node_exporter.tar.gz; then
    handle_error "Failed to extract Node Exporter"
fi

if ! mv node_exporter-${NODE_EXPORTER_VERSION}.linux-${NODE_EXPORTER_ARCH}/node_exporter /usr/local/bin/; then
    handle_error "Failed to move Node Exporter binary"
fi

# Clean up
cd - > /dev/null
rm -rf "$TEMP_DIR"

# Create systemd service for Node Exporter
if ! cat > /etc/systemd/system/node_exporter.service << EOL
[Unit]
Description=Node Exporter
After=network-online.target

[Service]
User=root
ExecStart=/usr/local/bin/node_exporter
Restart=always

[Install]
WantedBy=multi-user.target
EOL
then
    handle_error "Failed to create Node Exporter service file"
fi

# Verify Node Exporter version
if command_exists node_exporter; then
    NODE_EXP_VERSION=$(get_version node_exporter)
    if version_gt "$REQUIRED_NODE_EXPORTER_VERSION" "$NODE_EXP_VERSION"; then
        handle_error "Node Exporter version $NODE_EXP_VERSION is too old. Required: $REQUIRED_NODE_EXPORTER_VERSION"
    fi
fi

# Install Rust
echo -e "${YELLOW}Installing Rust...${NC}"
if ! curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; then
    handle_error "Failed to install Rust" "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable"
fi

source $HOME/.cargo/env

# Create Sarissa user and group
echo -e "${YELLOW}Creating Sarissa user and group...${NC}"
if ! getent group sarissa >/dev/null; then
    if ! groupadd sarissa; then
        handle_error "Failed to create sarissa group"
    fi
fi

if ! getent passwd sarissa >/dev/null; then
    if ! useradd -m -g sarissa -s /bin/bash sarissa; then
        handle_error "Failed to create sarissa user"
    fi
fi

# Create necessary directories
echo -e "${YELLOW}Creating necessary directories...${NC}"
for dir in /opt/sarissa /var/log/sarissa /var/backups/sarissa /etc/sarissa/ssl /opt/sarissa/plugins; do
    if ! mkdir -p "$dir"; then
        handle_error "Failed to create directory: $dir"
    fi
    if ! chown sarissa:sarissa "$dir"; then
        handle_error "Failed to set ownership for directory: $dir"
    fi
done

# Clone and build Sarissa
echo -e "${YELLOW}Building Sarissa...${NC}"
cd /opt/sarissa

# Prompt for repository URL
echo -e "${YELLOW}Please provide the Sarissa repository URL:${NC}"
echo -e "${YELLOW}Example: https://github.com/your-org/sarissa.git${NC}"
read -p "Repository URL: " REPO_URL

if [ -z "$REPO_URL" ]; then
    handle_error "Repository URL is required"
fi

# Clone the repository
echo -e "${YELLOW}Cloning repository...${NC}"
if ! git clone "$REPO_URL" .; then
    handle_error "Failed to clone repository" "git clone --depth 1 $REPO_URL ."
fi

if ! chown -R sarissa:sarissa .; then
    handle_error "Failed to set repository ownership"
fi

# Copy configuration files
echo -e "${YELLOW}Setting up configuration...${NC}"
if ! cp config.toml.example config.toml; then
    handle_error "Failed to copy configuration file"
fi

if ! chown sarissa:sarissa config.toml; then
    handle_error "Failed to set configuration file ownership"
fi

# Set up scripts
echo -e "${YELLOW}Setting up utility scripts...${NC}"
if ! chmod +x scripts/*.sh; then
    handle_error "Failed to make scripts executable"
fi

for script in backup.sh health_check.sh maintenance.sh; do
    if ! cp "scripts/$script" "/usr/local/bin/sarissa-${script%.sh}"; then
        handle_error "Failed to copy script: $script"
    fi
done

# Set up log rotation
echo -e "${YELLOW}Setting up log rotation...${NC}"
if ! cp logrotate.d/sarissa /etc/logrotate.d/; then
    handle_error "Failed to copy logrotate configuration"
fi

if ! chmod 644 /etc/logrotate.d/sarissa; then
    handle_error "Failed to set logrotate configuration permissions"
fi

# Set up cron jobs
echo -e "${YELLOW}Setting up scheduled tasks...${NC}"
for job in \
    "0 0 * * * /usr/local/bin/sarissa-backup" \
    "*/5 * * * * /usr/local/bin/sarissa-health-check" \
    "0 0 * * 0 /usr/local/bin/sarissa-maintenance clean"
do
    if ! (crontab -u sarissa -l 2>/dev/null; echo "$job") | crontab -u sarissa -; then
        handle_error "Failed to add cron job: $job"
    fi
done

# Build the application
echo -e "${YELLOW}Building application...${NC}"
if ! sudo -u sarissa cargo build --release; then
    handle_error "Failed to build application" "sudo -u sarissa cargo build --release --verbose"
fi

# Set up systemd service
echo -e "${YELLOW}Setting up systemd service...${NC}"
if ! cp sarissa.service /etc/systemd/system/; then
    handle_error "Failed to copy service file"
fi

if ! systemctl daemon-reload; then
    handle_error "Failed to reload systemd"
fi

if ! systemctl enable sarissa; then
    handle_error "Failed to enable Sarissa service"
fi

if ! systemctl start sarissa; then
    handle_error "Failed to start Sarissa service" "systemctl restart sarissa"
fi

# Set up Prometheus monitoring
echo -e "${YELLOW}Setting up monitoring...${NC}"
if ! cp prometheus.yml /etc/prometheus/; then
    handle_error "Failed to copy Prometheus configuration"
fi

if ! cp rules/sarissa_alerts.yml /etc/prometheus/rules/; then
    handle_error "Failed to copy Prometheus rules"
fi

if ! systemctl enable prometheus; then
    handle_error "Failed to enable Prometheus service"
fi

if ! systemctl enable node_exporter; then
    handle_error "Failed to enable Node Exporter service"
fi

if ! systemctl start prometheus; then
    handle_error "Failed to start Prometheus service" "systemctl restart prometheus"
fi

if ! systemctl start node_exporter; then
    handle_error "Failed to start Node Exporter service" "systemctl restart node_exporter"
fi

# Check service status
echo -e "${YELLOW}Checking service status...${NC}"
if ! systemctl is-active --quiet sarissa; then
    handle_error "Sarissa service failed to start" "journalctl -u sarissa"
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