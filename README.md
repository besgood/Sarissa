# Sarissa

A modern network penetration testing tool with a GUI interface, inspired by Sparta and ported to Rust.

## Features
- Fast network scanning and vulnerability detection
- Exploit execution and chaining (Metasploit integration)
- Plugin system with marketplace
- Real-time collaboration and workspaces
- Role-based access control and audit logging
- Dashboard with real-time metrics and Prometheus integration
- Modern, cross-platform GUI (egui/eframe)

## Quickstart

### Prerequisites
- Rust (1.70+ recommended)
- PostgreSQL (13+)
- [nmap](https://nmap.org/), [sqlmap](https://sqlmap.org/), and other common security tools in `$PATH`

### Database Setup
```
sudo -u postgres createuser sarissa --createdb --login --pwprompt
sudo -u postgres createdb sarissa --owner=sarissa
# Set password to 'sarissa' or update config.toml accordingly
```

### Configuration
Edit `config.toml` to match your environment. See the provided sample for all options.

### Build & Run
```
cargo build --release
./target/release/sarissa
```

### GUI
- The GUI will launch automatically.

### Prometheus Metrics
- Metrics are available at `http://127.0.0.1:8081/metrics` (if your main server is on 8080).
- Example Prometheus scrape config:
  ```yaml
  scrape_configs:
    - job_name: 'sarissa'
      static_configs:
        - targets: ['127.0.0.1:8081']
  ```

## Directory Structure
- `src/` - Main application code
- `migrations/` - Database schema (run automatically on startup)
- `config.toml` - Main configuration file

## Troubleshooting
- **Database connection errors:** Ensure PostgreSQL is running and the user/database match your config.
- **Missing tools:** Ensure required tools (nmap, sqlmap, etc.) are installed and in your `$PATH`.
- **Metrics not available:** Ensure port 8081 (or your configured metrics port) is open and not blocked.
- **Log files:** See `logs/` for application logs.

## Security
- Change all default secrets in `config.toml` before production use.
- Use strong passwords for database and JWT secrets.
- Restrict access to the metrics endpoint as needed.

## License
MIT 