# Sarissa Security Platform

A comprehensive security platform for vulnerability assessment and management.

## ⚠️ Important Disclaimer

**USE AT YOUR OWN RISK**

This software is provided for educational and research purposes only. Please read the full [Disclaimer](docs/DISCLAIMER.md) before using this software. By using Sarissa, you acknowledge that you have read and understood the disclaimer and agree to be bound by its terms.

## 🔒 Privacy-Focused

Sarissa is designed with privacy as a core principle:
- No data collection or telemetry
- No internet communication
- All data stored locally
- No third-party services
- Complete control over your data

For detailed privacy information, see our [Privacy and Data Collection](docs/DISCLAIMER.md#privacy-and-data-collection) section.

## Installation

1. Clone this repository:
```bash
git clone https://github.com/YOUR_USERNAME/sarissa.git
cd sarissa
```

2. Run the setup script:
```bash
sudo ./setup.sh
```

The setup script will:
- Install all required dependencies
- Set up PostgreSQL database
- Configure the systemd service
- Build and deploy Sarissa

## Configuration

After installation, you'll need to:
1. Change the default database password in `/opt/sarissa/config.toml`
2. Review and adjust the configuration file
3. Set up SSL certificates if needed

## Usage

Sarissa runs as a systemd service and is accessible on:
- Port 8080: Main application
- Port 8081: API endpoints

## Logs

Logs are available in:
- `/var/log/sarissa/sarissa.log`
- `/var/log/sarissa/sarissa.err`

## Docker Support

A Dockerfile is included for containerized deployment. Build and run with:
```bash
docker build -t sarissa .
docker run -p 8080:8080 -p 8081:8081 sarissa
```

## Documentation

For detailed documentation, please refer to:
- [Architecture](docs/ARCHITECTURE.md)
- [API Documentation](docs/API.md)
- [Contributing Guide](docs/CONTRIBUTING.md)
- [Disclaimer](docs/DISCLAIMER.md)

## License

[Your chosen license] 