#!/bin/bash

# Exit on error
set -e

# Load configuration
source /opt/sarissa/config.toml

# Set variables
BACKUP_DIR="/var/backups/sarissa"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/sarissa_backup_$DATE"
RETENTION_DAYS=30

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

# Backup PostgreSQL database
echo "Backing up database..."
pg_dump -U sarissa -F c sarissa > "$BACKUP_FILE.db"

# Backup configuration files
echo "Backing up configuration..."
tar -czf "$BACKUP_FILE.config.tar.gz" /opt/sarissa/config.toml /etc/sarissa/ssl/

# Backup logs
echo "Backing up logs..."
tar -czf "$BACKUP_FILE.logs.tar.gz" /var/log/sarissa/

# Create backup archive
echo "Creating backup archive..."
tar -czf "$BACKUP_FILE.tar.gz" \
    "$BACKUP_FILE.db" \
    "$BACKUP_FILE.config.tar.gz" \
    "$BACKUP_FILE.logs.tar.gz"

# Clean up temporary files
rm "$BACKUP_FILE.db" "$BACKUP_FILE.config.tar.gz" "$BACKUP_FILE.logs.tar.gz"

# Remove old backups
echo "Cleaning up old backups..."
find "$BACKUP_DIR" -name "sarissa_backup_*.tar.gz" -mtime +$RETENTION_DAYS -delete

echo "Backup completed: $BACKUP_FILE.tar.gz" 