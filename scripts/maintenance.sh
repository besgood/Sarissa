#!/bin/bash

# Exit on error
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root${NC}"
    exit 1
fi

# Function to display usage
usage() {
    echo "Usage: $0 [command]"
    echo "Commands:"
    echo "  status    - Check system status"
    echo "  restart   - Restart Sarissa service"
    echo "  logs      - Show recent logs"
    echo "  clean     - Clean old logs and backups"
    echo "  backup    - Create manual backup"
    echo "  update    - Update Sarissa"
    echo "  repair    - Repair database"
    exit 1
}

# Check system status
check_status() {
    echo -e "${YELLOW}Checking system status...${NC}"
    systemctl status sarissa
    systemctl status prometheus
    systemctl status node-exporter
    echo -e "${YELLOW}Disk usage:${NC}"
    df -h /var
    echo -e "${YELLOW}Memory usage:${NC}"
    free -h
}

# Restart service
restart_service() {
    echo -e "${YELLOW}Restarting Sarissa service...${NC}"
    systemctl restart sarissa
    echo -e "${GREEN}Service restarted${NC}"
}

# Show recent logs
show_logs() {
    echo -e "${YELLOW}Recent logs:${NC}"
    tail -n 50 /var/log/sarissa/sarissa.log
}

# Clean old files
clean_old_files() {
    echo -e "${YELLOW}Cleaning old files...${NC}"
    find /var/log/sarissa -name "*.log.*" -mtime +14 -delete
    find /var/backups/sarissa -name "sarissa_backup_*.tar.gz" -mtime +30 -delete
    echo -e "${GREEN}Cleanup completed${NC}"
}

# Create manual backup
create_backup() {
    echo -e "${YELLOW}Creating manual backup...${NC}"
    /usr/local/bin/sarissa-backup
}

# Update Sarissa
update_sarissa() {
    echo -e "${YELLOW}Updating Sarissa...${NC}"
    cd /opt/sarissa
    git pull
    sudo -u sarissa cargo build --release
    systemctl restart sarissa
    echo -e "${GREEN}Update completed${NC}"
}

# Repair database
repair_database() {
    echo -e "${YELLOW}Repairing database...${NC}"
    sudo -u postgres psql -d sarissa -c "VACUUM FULL;"
    sudo -u postgres psql -d sarissa -c "REINDEX DATABASE sarissa;"
    echo -e "${GREEN}Database repair completed${NC}"
}

# Main script
case "$1" in
    status)
        check_status
        ;;
    restart)
        restart_service
        ;;
    logs)
        show_logs
        ;;
    clean)
        clean_old_files
        ;;
    backup)
        create_backup
        ;;
    update)
        update_sarissa
        ;;
    repair)
        repair_database
        ;;
    *)
        usage
        ;;
esac 