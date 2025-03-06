# FireMon Change Detection to Microsoft Sentinel Integration

This project provides an automated integration between FireMon's syslog change notifications and Microsoft Sentinel, enhancing security monitoring and compliance tracking capabilities.

## Overview

When FireMon detects configuration changes on network devices, it generates syslog messages. This integration:

1. Captures these syslog messages using syslog-ng
2. Extracts key information such as device name, revision number, and timestamp
3. Makes API calls to FireMon to retrieve detailed information about the changes
4. Collects associated control failures and rule violations
5. Formats and forwards all data to Microsoft Sentinel for analysis and alerting

## Components

- **firemon_alerts.conf**: syslog-ng configuration for parsing FireMon change notifications
- **firemon_api_fetch.py**: Python script for retrieving detailed change information from FireMon APIs
- **sentinel_integration.py**: Module for sending data to Azure Sentinel Log Analytics
- **api_fetch.conf**: Configuration file for API credentials and settings
- **install.sh**: Installation script for easy deployment

## Requirements

- syslog-ng (3.x or later)
- Python 3.6+
- Python packages: `requests`, `configparser`
- FireMon Security Manager with API access
- Microsoft Sentinel (Azure Log Analytics workspace)

## Installation

1. Clone this repository or download the files to your syslog-ng server:

```bash
git clone https://github.com/adamgunderson/firemon-sentinel-integration.git
cd firemon-sentinel-integration
```

2. Run the installation script:

```bash
chmod +x install.sh
./install.sh
```

The script will:
- Create necessary directories
- Copy configuration files to appropriate locations
- Set proper permissions
- Install required Python dependencies
- Restart syslog-ng (if it's running)

## Configuration

### 1. FireMon API and Sentinel Credentials

Edit the configuration file `/etc/firemon/api_fetch.conf`:

```bash
vi /etc/firemon/api_fetch.conf
```

Update the following sections:

```ini
[api]
username = your-firemon-username
password = your-firemon-password
verify_ssl = false  # Set to true in production if using valid SSL certs

[sentinel]
enabled = true
workspace_id = your-workspace-id-here
shared_key = your-shared-key-here
log_type = FireMonChangeLog
```

### 2. syslog-ng Configuration

The integration assumes you have a source defined in your syslog-ng configuration. Ensure your main syslog-ng.conf includes the conf.d directory:

```
@include "/etc/syslog-ng/conf.d/*.conf"
```

If you need to modify the syslog source, edit `/etc/syslog-ng/conf.d/firemon_alerts.conf` and update the source reference:

```
log {
    source(your_source_name); # Change this to match your syslog source
    filter(f_firemon_changes);
    parser(firemon_change_parser());
    destination(d_firemon_api_fetch);
};
```

## Usage

Once installed and configured, the integration works automatically:

1. FireMon sends a syslog message when changes are detected
2. syslog-ng captures the message and triggers the Python script
3. The script collects detailed information from FireMon API
4. All data is forwarded to Microsoft Sentinel
5. Logs are stored in `/var/log/firemon/` for debugging

### Manual Testing

You can manually test the integration by running:

```bash
/usr/local/bin/firemon_api_fetch.py \
  --device-name="vSRX Live - B" \
  --revision=78069 \
  --user=hsimpson \
  --timestamp="2023-01-24T20:24:13.861168" \
  --server=demo.firemon.xyz
```

## Data in Sentinel

In Sentinel, the data will appear as custom logs with the type specified in your configuration (default: `FireMonChangeLog_CL`). Each log entry will contain:

- Basic information from the syslog message (device name, revision, user, timestamp)
- Detailed changelog showing what changed in the specified revision
- Rules with control failures associated with the change
- Specific control failures for each affected rule

## Troubleshooting

Check these log files for troubleshooting:

- `/var/log/firemon_api_fetch.log`: Main script logs
- `/var/log/firemon/revision_[NUMBER]_data.json`: JSON data collected for each revision
- Syslog logs (location varies by system)

Common issues:

1. **Authentication failures**: Verify FireMon API credentials in the config file
2. **Connection errors**: Ensure the FireMon server is reachable and API is enabled
3. **SSL issues**: Try setting `verify_ssl = false` if using self-signed certificates
4. **Parsing errors**: Check if FireMon syslog format has changed and update regex in `firemon_alerts.conf`

## Customization

### Adjusting Pagination

For large environments with many changes, you may need to adjust pagination settings in `firemon_api_fetch.py`:

```python
all_changelog_entries = handle_pagination(
    get_changelog, args.server, token, actual_device_id, args.revision, page_size=25  # Increased from 10
)
```

### Adding Additional Destinations

You can add more destinations in `firemon_alerts.conf` to store raw messages:

```
destination d_firemon_file {
    file("/var/log/firemon/changes.log");
};

log {
    source(s_src);
    filter(f_firemon_changes);
    parser(firemon_change_parser());
    destination(d_firemon_api_fetch);
    destination(d_firemon_file);  # Added file destination
};
```

## Security Considerations

- Store API credentials securely
- Use proper permissions for config files
- Consider encrypting sensitive log files
- In production, enable SSL verification by setting `verify_ssl = true`
- Implement proper error handling to prevent information leakage
