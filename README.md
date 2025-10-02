#Dynamic DNS IP Updater using Namcheap HTTPS requests + UniFi API

Menu-driven interactive terminal interface to  dynamically update the host's IP with an HTTPS requestNameCheap Dynamic DNS pulled from Ubiquiti Uni devices using Unifi Cloud API

## Overview

This interactive application provides a user-friendly terminal interface with styled menus, tables, and status displays for monitoring and updating your Namecheap Dynamic DNS records from Unifi devices. Built with the Rich library for Python, it offers a modern CLI experience with color-coded output and intuitive navigation.

The script uses NameCheap HTTPS request URL https://dynamicdns.park-your-domain.com/update


## Features

- **Rich Terminal UI**: Interface with tables, panels, and color-coded output
- **Interactive Menus**: Easy-to-navigate menu system with 9 main options
- **Real-Time Status**: View current WAN IP, update history, and configuration
- **DNS Management**: Update DNS records with optional confirmation prompts
- **Daemon Mode**: Run continuously with automatic IP monitoring
- **Connection Testing**: Test both UniFi and NameCheap API connections
- **Log Viewer**: View recent log entries with color-coded severity levels
- **Configuration Management**: Create, load, and reload configuration interactively

## Requirements

### Python Version
- Python 3.8 or higher

### Dependencies
```bash
pip install rich>=13.7.0 requests>=2.31.0 urllib3>=2.0.0
```

### Required Files
- `ddns_interactive.py` - Standalone application (all code embedded)
- `config.json` - Configuration file (will be created on first run if missing)

## Installation

1. **Clone or download the repository**
   ```bash
   git clone <repository-url>
   cd <repository-directory>
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

   Or install manually:
   ```bash
   pip install rich requests urllib3
   ```

3. **Prepare configuration**
   - The application will prompt you to create a configuration file on first run
   - Or manually create `config.json` (see Configuration section below)

## Configuration

### config.json Format

Create a `config.json` file with the following structure:

```json
{
  "unifi_host": "api.ui.com",
  "unifi_api_key": "YOUR_UNIFI_API_KEY_HERE",
  "namecheap_host": "subdomain",
  "namecheap_domain": "yourdomain.com",
  "namecheap_password": "YOUR_DDNS_PASSWORD_HERE",
  "unifi_verify_ssl": true,
  "check_interval": 300,
  "state_file": "ddns_state.json",
  "log_file": "ddns_updater.log",
  "log_level": "INFO",
  "max_retries": 3,
  "retry_delay": 5
}
```

### Configuration Fields

| Field | Description | Required | Default |
|-------|-------------|----------|---------|
| `unifi_host` | UniFi Cloud API host | Yes | `api.ui.com` |
| `unifi_api_key` | Your UniFi Cloud API key | Yes | - |
| `namecheap_host` | Subdomain for DDNS (e.g., "www", "cameras") | Yes | - |
| `namecheap_domain` | Your domain name | Yes | - |
| `namecheap_password` | NameCheap Dynamic DNS password | Yes | - |
| `unifi_verify_ssl` | Verify SSL certificates | No | `true` |
| `check_interval` | Seconds between IP checks (daemon mode) | No | `300` |
| `state_file` | Path to state persistence file | No | `ddns_state.json` |
| `log_file` | Path to log file | No | `ddns_updater.log` |
| `log_level` | Logging level (DEBUG/INFO/WARNING/ERROR) | No | `INFO` |
| `max_retries` | Maximum retry attempts for failed operations | No | `3` |
| `retry_delay` | Seconds to wait between retries | No | `5` |

### Obtaining API Credentials

#### UniFi Cloud API Key
1. Log in to [unifi.ui.com](https://unifi.ui.com)
2. Navigate to Settings → API
3. Generate a new API key
4. Copy the key to your `config.json`

#### NameCheap Dynamic DNS Password
1. Log in to your NameCheap account
2. Go to Domain List → Manage
3. Navigate to Advanced DNS
4. Enable Dynamic DNS
5. Copy the Dynamic DNS password to your `config.json`

## Usage

### Starting the Application

#### Windows
```cmd
python ddns_interactive.py
```

Or using Python 3 explicitly:
```cmd
py -3 ddns_interactive.py
```

#### Linux/macOS
```bash
python3 ddns_interactive.py
```

Or make it executable:
```bash
chmod +x ddns_interactive.py
./ddns_interactive.py
```

### Main Menu Options

Once started, you'll see an interactive menu with the following options:

#### 1. View Current Status
- Displays current configuration summary
- Shows last known IP address
- Shows update history and counters
- Displays last check and update timestamps

#### 2. Check WAN IP
- Retrieves current WAN IP from UniFi Cloud API
- Compares with last known IP
- Shows whether IP has changed
- Does NOT update DNS

#### 3. Update DNS (with confirmation)
- Retrieves current WAN IP
- Shows comparison with last known IP
- Prompts for confirmation before updating
- Option to force update even if IP hasn't changed
- Updates NameCheap DNS record

#### 4. Update DNS (force, no confirmation)
- Same as option 3 but skips confirmation
- Useful for scripting or when you're certain

#### 5. Run Daemon Mode
- Runs continuously in the background
- Checks IP at configured intervals (default: 5 minutes)
- Automatically updates DNS when IP changes
- Press Ctrl+C to stop
- **Warning**: Will run indefinitely until stopped

#### 6. Test Connections
- Tests UniFi Cloud API connectivity
- Retrieves WAN IP as a test
- Optionally tests NameCheap DDNS update
- **Note**: NameCheap test will actually update your DNS

#### 7. View Recent Logs
- Shows last 20 log entries
- Color-coded by severity:
  - Green: INFO
  - Yellow: WARNING
  - Red: ERROR

#### 8. Reload Configuration
- Reloads `config.json` from disk
- Useful after manually editing configuration
- Reinitializes connections with new settings

#### 0. Exit
- Cleanly exits the application

### First Run Workflow

1. **Start the application**
   ```bash
   python3 ddns_interactive.py
   ```

2. **Create configuration**
   - When prompted, select "Yes" to create configuration
   - Enter your UniFi API key
   - Enter your subdomain (e.g., "cameras")
   - Enter your domain (e.g., "example.com")
   - Enter your NameCheap Dynamic DNS password
   - Enter check interval (or use default 300 seconds)

3. **Test connections** (recommended)
   - Select option 6 from main menu
   - Verify UniFi API connection works
   - Optionally test NameCheap update

4. **Check current IP**
   - Select option 2 to see your current WAN IP

5. **Update DNS**
   - Select option 3 for confirmed update
   - Review the information displayed
   - Confirm the update when prompted

6. **Optional: Run daemon mode**
   - Select option 5 to run continuous monitoring
   - Press Ctrl+C to stop when needed

## File Structure

```
project-directory/
├── ddns_interactive.py     # Standalone interactive interface (all-in-one)
├── requirements.txt        # Python dependencies
├── config.json             # Configuration file (auto-created on first run)
├── ddns_state.json         # State persistence (auto-created on first run)
└── ddns_updater.log        # Log file (auto-created on first run)
```

**Note**: This is a standalone application. All required code is embedded in `ddns_interactive.py` - no additional Python files are needed.

## State Management

The application maintains state in `ddns_state.json`:

```json
{
  "last_ip": "203.0.113.1",
  "last_update": "2025-10-01T15:32:04",
  "last_check": "2025-10-01T15:34:00",
  "update_count": 5,
  "error_count": 0
}
```

This file is automatically created and updated. Do not edit manually.

## Logging

Logs are written to `ddns_updater.log` with rotation support:
- Maximum file size: 10 MB
- Backup count: 5 files
- Format: `YYYY-MM-DD HH:MM:SS - LEVEL - Message`

Example log entries:
```
2025-10-01 15:30:00 - INFO - Retrieved WAN IP: 203.0.113.1
2025-10-01 15:30:05 - INFO - Successfully updated DNS to 203.0.113.1
2025-10-01 15:35:00 - INFO - IP unchanged (203.0.113.1), no update needed
```

## Troubleshooting

### "Required package 'rich' not installed"
**Solution**: Install the rich library
```bash
pip install rich
```

### "Configuration file not found"
**Solution**: Create configuration interactively (option provided on startup) or manually create `config.json`

### "401 Unauthorized" from UniFi API
**Causes**:
- Invalid or expired API key
- API key doesn't have proper permissions

**Solution**:
1. Generate a new API key at unifi.ui.com
2. Update `unifi_api_key` in `config.json`
3. Reload configuration (option 8)

### "Failed to retrieve WAN IP"
**Causes**:
- No internet connection
- UniFi Cloud API is down
- Invalid API key
- Host configuration incorrect

**Solution**:
1. Check internet connectivity
2. Verify `unifi_host` is set to `api.ui.com`
3. Test connection (option 6)
4. Check logs (option 7)

### NameCheap Update Fails
**Causes**:
- Dynamic DNS not enabled for domain
- Incorrect DDNS password
- Wrong host/domain combination
- NameCheap API rate limiting

**Solution**:
1. Verify Dynamic DNS is enabled in NameCheap dashboard
2. Check `namecheap_password` in config.json
3. Verify `namecheap_host` and `namecheap_domain` are correct
4. Wait a few minutes if rate limited

### Cannot Import from ddns_updater
**Cause**: Missing `ddns_updater.py` file

**Solution**: Ensure `ddns_updater.py` is in the same directory as `ddns_interactive.py`

## Best Practices

### Security
1. **Protect your configuration**: `config.json` contains sensitive credentials
   ```bash
   chmod 600 config.json
   ```

2. **Don't commit credentials**: Add to `.gitignore`
   ```
   config.json
   ddns_state.json
   *.log
   ```

3. **Use API keys**: Never use your main UniFi account credentials

4. **Rotate keys regularly**: Change API keys periodically

### Usage
1. **Test first**: Always use option 6 to test connections before running daemon mode

2. **Monitor logs**: Regularly check logs (option 7) for errors or issues

3. **Reasonable intervals**: Don't set `check_interval` too low (recommended minimum: 60 seconds)

4. **Daemon mode caution**: Daemon mode runs indefinitely - ensure you want continuous monitoring

5. **Confirmation prompts**: Use option 3 (with confirmation) unless you're certain about updates

## Performance

### Resource Usage
- Memory: ~50-80 MB (includes Rich library)
- CPU: <1% idle, <5% during updates
- Network: ~2-3 KB per check

### Timing
- UniFi API response: 100-500ms
- NameCheap update: 50-200ms
- Menu navigation: Instant

## Advanced Usage

### Running as a Background Service

#### Linux (systemd)
Create `/etc/systemd/system/ddns-updater.service`:
```ini
[Unit]
Description=NameCheap DDNS Updater
After=network.target

[Service]
Type=simple
User=your-user
WorkingDirectory=/path/to/ddns
ExecStart=/usr/bin/python3 /path/to/ddns/ddns_interactive.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable ddns-updater
sudo systemctl start ddns-updater
```

#### macOS (launchd)
Create `~/Library/LaunchAgents/com.ddns.updater.plist`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.ddns.updater</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>/path/to/ddns_interactive.py</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```

Load:
```bash
launchctl load ~/Library/LaunchAgents/com.ddns.updater.plist
```

### Scripting

For automated/scripted usage, consider using the CLI version (`ddns_updater.py`) instead:
```bash
# Run once
python3 ddns_updater.py once --no-confirm

# Run daemon
python3 ddns_updater.py daemon
```

## API Rate Limits

### UniFi Cloud API
- No documented rate limit
- Recommended: 1 request per minute maximum

### NameCheap Dynamic DNS
- Recommended: Update only on IP change
- Avoid updates more frequent than once per minute

## Changelog

### Version 1.0
- Initial release
- Rich-based interactive interface
- 9 menu options
- Configuration creation wizard
- Connection testing
- Log viewer
- Daemon mode support
- Color-coded output

## License

This project is provided as-is without warranty. See LICENSE file for details.

## Support

For issues, questions, or contributions:
1. Check this README thoroughly
2. Review log files for error details
3. Test connections using option 6
4. Verify configuration settings
5. Check API credentials validity

## Related Files

- **ddns_updater.py**: Core CLI version with full functionality
- **ddns_silent.py**: Silent version for automation/scheduling
- **ddns_gui.py**: GUI version with CustomTkinter interface

## Credits

Built with:
- [Rich](https://github.com/Textualize/rich) - Beautiful terminal formatting
- [Requests](https://requests.readthedocs.io/) - HTTP library
- Python 3.8+

## Notes

- This interactive version is ideal for manual management and monitoring
- For automated/scheduled tasks, use the silent version (`ddns_silent.py`)
- For visual desktop application, use the GUI version (`ddns_gui.py`)
- The interactive version requires a terminal that supports ANSI color codes
- Best experienced in a terminal with good Unicode support

---

**Last Updated**: 2025-10-01
**Version**: 1.0
**Python**: 3.8+
**Status**: Production Ready
