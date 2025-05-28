#!/bin/bash

# Exit on error
set -e

# Configuration
HEALTH_CHECK_FILE="/var/log/sarissa/health_check.log"
MAX_LOG_SIZE=10485760  # 10MB
MAX_LOG_FILES=5

# Check if service is running
check_service() {
    if ! systemctl is-active --quiet sarissa; then
        echo "ERROR: Sarissa service is not running"
        return 1
    fi
    return 0
}

# Check database connection
check_database() {
    if ! psql -U sarissa -d sarissa -c "SELECT 1" > /dev/null 2>&1; then
        echo "ERROR: Cannot connect to database"
        return 1
    fi
    return 0
}

# Check disk space
check_disk_space() {
    local threshold=90
    local usage=$(df -h /var | awk 'NR==2 {print $5}' | sed 's/%//')
    if [ "$usage" -gt "$threshold" ]; then
        echo "WARNING: Disk usage is above $threshold%"
        return 1
    fi
    return 0
}

# Check memory usage
check_memory() {
    local threshold=90
    local usage=$(free | awk '/Mem:/ {print int($3/$2 * 100)}')
    if [ "$usage" -gt "$threshold" ]; then
        echo "WARNING: Memory usage is above $threshold%"
        return 1
    fi
    return 0
}

# Check CPU load
check_cpu_load() {
    local threshold=80
    local load=$(uptime | awk -F'load average:' '{ print $2 }' | cut -d, -f1 | tr -d ' ')
    if (( $(echo "$load > $threshold" | bc -l) )); then
        echo "WARNING: CPU load is above $threshold"
        return 1
    fi
    return 0
}

# Rotate log file if needed
rotate_log() {
    if [ -f "$HEALTH_CHECK_FILE" ]; then
        local size=$(stat -f%z "$HEALTH_CHECK_FILE" 2>/dev/null || stat -c%s "$HEALTH_CHECK_FILE")
        if [ "$size" -gt "$MAX_LOG_SIZE" ]; then
            for ((i=$MAX_LOG_FILES-1; i>=1; i--)); do
                if [ -f "${HEALTH_CHECK_FILE}.$i" ]; then
                    mv "${HEALTH_CHECK_FILE}.$i" "${HEALTH_CHECK_FILE}.$((i+1))"
                fi
            done
            mv "$HEALTH_CHECK_FILE" "${HEALTH_CHECK_FILE}.1"
        fi
    fi
}

# Main health check
main() {
    local status=0
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local output="[$timestamp] Health check started\n"

    # Run all checks
    if ! check_service; then
        output+="[$timestamp] Service check failed\n"
        status=1
    fi

    if ! check_database; then
        output+="[$timestamp] Database check failed\n"
        status=1
    fi

    if ! check_disk_space; then
        output+="[$timestamp] Disk space check failed\n"
        status=1
    fi

    if ! check_memory; then
        output+="[$timestamp] Memory check failed\n"
        status=1
    fi

    if ! check_cpu_load; then
        output+="[$timestamp] CPU load check failed\n"
        status=1
    fi

    # Add summary
    if [ $status -eq 0 ]; then
        output+="[$timestamp] All checks passed\n"
    else
        output+="[$timestamp] Some checks failed\n"
    fi

    # Rotate and write to log
    rotate_log
    echo -e "$output" >> "$HEALTH_CHECK_FILE"

    return $status
}

# Run main function
main 