#!/usr/bin/env python3
"""
Interactive Menu-Driven Interface for NameCheap Dynamic DNS + UniFi Application
Standalone version with all dependencies embedded
"""

import sys
import json
import logging
import time
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass, asdict
from logging.handlers import RotatingFileHandler
from datetime import datetime

# Import requests and urllib3
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Import Rich for UI
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt, Confirm
    from rich.text import Text
    from rich import box
except ImportError:
    print("Error: Required package 'rich' not installed.")
    print("Please install it with: pip install rich")
    sys.exit(1)


# ============================================================================
# CONFIGURATION
# ============================================================================

@dataclass
class Config:
    """Application configuration."""
    # UniFi Settings (required fields first)
    unifi_host: str
    unifi_api_key: str

    # NameCheap Settings (required fields)
    namecheap_host: str
    namecheap_domain: str
    namecheap_password: str

    # Optional fields with defaults (must come after required fields)
    unifi_verify_ssl: bool = True
    check_interval: int = 300  # seconds
    state_file: str = "ddns_state.json"
    log_file: str = "ddns_updater.log"
    log_level: str = "INFO"
    max_retries: int = 3
    retry_delay: int = 5

    @classmethod
    def from_file(cls, config_path: str) -> 'Config':
        """Load configuration from JSON file."""
        with open(config_path, 'r') as f:
            data = json.load(f)
        return cls(**data)


# ============================================================================
# EXCEPTIONS
# ============================================================================

class DDNSException(Exception):
    """Base exception for DDNS application."""
    pass


class UniFiAPIException(DDNSException):
    """Exception for UniFi API errors."""
    pass


class NameCheapException(DDNSException):
    """Exception for NameCheap API errors."""
    pass


# ============================================================================
# LOGGING SETUP
# ============================================================================

def setup_logging(log_file: str, log_level: str, verbose: bool = False) -> logging.Logger:
    """Configure logging with rotating file handler and console output."""
    logger = logging.getLogger('ddns_updater')
    logger.setLevel(getattr(logging, log_level.upper()))

    # Clear existing handlers
    logger.handlers.clear()

    # File handler with rotation
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    )
    console_handler.setFormatter(console_formatter)
    if verbose:
        console_handler.setLevel(logging.DEBUG)
    logger.addHandler(console_handler)

    return logger


# ============================================================================
# STATE MANAGEMENT
# ============================================================================

@dataclass
class State:
    """Application state."""
    last_ip: Optional[str] = None
    last_update: Optional[str] = None
    last_check: Optional[str] = None
    update_count: int = 0
    error_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert state to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'State':
        """Create state from dictionary."""
        return cls(**data)


class StateManager:
    """Manages persistent application state."""

    def __init__(self, state_file: str, logger: logging.Logger):
        self.state_file = Path(state_file)
        self.logger = logger
        self.state = self.load()

    def load(self) -> State:
        """Load state from file."""
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r') as f:
                    data = json.load(f)
                self.logger.info(f"Loaded state from {self.state_file}")
                return State.from_dict(data)
            except Exception as e:
                self.logger.error(f"Error loading state: {e}")
        return State()

    def save(self):
        """Save state to file."""
        try:
            with open(self.state_file, 'w') as f:
                json.dump(self.state.to_dict(), f, indent=2)
            self.logger.debug(f"Saved state to {self.state_file}")
        except Exception as e:
            self.logger.error(f"Error saving state: {e}")

    def update_ip(self, ip: str):
        """Update IP address in state."""
        self.state.last_ip = ip
        self.state.last_update = datetime.now().isoformat()
        self.state.update_count += 1
        self.save()

    def update_check(self):
        """Update last check time."""
        self.state.last_check = datetime.now().isoformat()
        self.save()

    def increment_error(self):
        """Increment error count."""
        self.state.error_count += 1
        self.save()


# ============================================================================
# UNIFI API CLIENT
# ============================================================================

class UniFiClient:
    """Client for UniFi Cloud API."""

    def __init__(self, config: Config, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.session = self._create_session()
        # Use cloud API endpoint
        self.base_url = "https://api.ui.com"
        self.api_key = config.unifi_api_key

    def _create_session(self) -> requests.Session:
        """Create requests session with retry logic."""
        session = requests.Session()
        retry = Retry(
            total=self.config.max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('https://', adapter)
        session.mount('http://', adapter)
        return session

    def get_wan_ip(self) -> Optional[str]:
        """Get WAN IP address from UniFi Cloud API."""
        try:
            if not self.api_key:
                raise UniFiAPIException("UniFi API key is required")

            # Call UniFi Cloud API v1/hosts endpoint
            url = f"{self.base_url}/v1/hosts"
            headers = {
                'X-API-KEY': self.api_key,
                'Accept': 'application/json'
            }

            self.logger.debug(f"Requesting WAN IP from {url}")

            response = self.session.get(
                url,
                headers=headers,
                timeout=30
            )

            if response.status_code == 429:
                self.logger.error("Rate limit exceeded (429). Check Retry-After header.")
                retry_after = response.headers.get('Retry-After', 'unknown')
                raise UniFiAPIException(f"Rate limit exceeded. Retry after {retry_after} seconds")

            if response.status_code != 200:
                self.logger.error(f"UniFi API error: {response.status_code} - {response.text}")
                raise UniFiAPIException(f"API returned status {response.status_code}")

            data = response.json()
            self.logger.debug(f"UniFi API response: {json.dumps(data, indent=2)}")

            # Extract WAN IP from hosts response
            wan_ip = self._extract_wan_ip(data)
            if wan_ip:
                self.logger.info(f"Retrieved WAN IP: {wan_ip}")
                return wan_ip
            else:
                raise UniFiAPIException("Could not extract WAN IP from API response")

        except Exception as e:
            self.logger.error(f"Error getting WAN IP: {e}")
            raise UniFiAPIException(f"Failed to get WAN IP: {e}")

    def _extract_wan_ip(self, data: Dict) -> Optional[str]:
        """Extract WAN IP from UniFi Cloud API response."""
        try:
            # Response is a dict with 'data' array
            hosts = data.get('data', [])

            if not isinstance(hosts, list) or len(hosts) == 0:
                self.logger.error("No hosts found in API response")
                return None

            # Process first host (usually the console/gateway)
            host = hosts[0]

            # Try reportedState.ip first (most reliable)
            if 'reportedState' in host:
                reported_state = host['reportedState']

                # Direct IP field
                if 'ip' in reported_state and reported_state['ip']:
                    ip = reported_state['ip']
                    # Filter out private IPs
                    if not self._is_private_ip(ip):
                        return ip

                # Check wans array for IPv4 address
                if 'wans' in reported_state and isinstance(reported_state['wans'], list):
                    for wan in reported_state['wans']:
                        if wan.get('enabled') and wan.get('plugged'):
                            ipv4 = wan.get('ipv4', '')
                            if ipv4 and not self._is_private_ip(ipv4):
                                return ipv4

            # Fallback: check top-level ipAddress field
            if 'ipAddress' in host and host['ipAddress']:
                ip = host['ipAddress']
                if not self._is_private_ip(ip):
                    return ip

        except Exception as e:
            self.logger.error(f"Error extracting WAN IP: {e}")

        return None

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is a private/local address."""
        if not ip or not isinstance(ip, str):
            return True

        # Filter out private IP ranges
        private_ranges = [
            '10.', '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
            '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
            '172.30.', '172.31.', '192.168.', '127.', 'fe80::', '::'
        ]

        for prefix in private_ranges:
            if ip.startswith(prefix):
                return True

        return False


# ============================================================================
# NAMECHEAP DYNAMIC DNS CLIENT
# ============================================================================

class NameCheapDDNSClient:
    """Client for NameCheap Dynamic DNS API."""

    def __init__(self, config: Config, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.base_url = "https://dynamicdns.park-your-domain.com/update"

    def update_ip(self, ip: str) -> bool:
        """Update DNS record with new IP address."""
        try:
            params = {
                'host': self.config.namecheap_host,
                'domain': self.config.namecheap_domain,
                'password': self.config.namecheap_password,
                'ip': ip
            }

            self.logger.info(f"Updating NameCheap DNS: {self.config.namecheap_host}.{self.config.namecheap_domain} -> {ip}")

            response = requests.get(
                self.base_url,
                params=params,
                timeout=30
            )

            if response.status_code == 200:
                # Parse XML response
                if '<ErrCount>0</ErrCount>' in response.text or 'IP address set to' in response.text:
                    self.logger.info(f"Successfully updated DNS record to {ip}")
                    return True
                else:
                    self.logger.error(f"NameCheap update failed: {response.text}")
                    raise NameCheapException(f"Update failed: {response.text}")
            else:
                self.logger.error(f"NameCheap API error: {response.status_code} - {response.text}")
                raise NameCheapException(f"API error: {response.status_code}")

        except Exception as e:
            self.logger.error(f"Error updating NameCheap DNS: {e}")
            raise NameCheapException(f"Failed to update DNS: {e}")


# ============================================================================
# MAIN DDNS UPDATER
# ============================================================================

class DDNSUpdater:
    """Main DDNS updater application."""

    def __init__(self, config: Config, logger: logging.Logger, require_confirmation: bool = False):
        self.config = config
        self.logger = logger
        self.state_manager = StateManager(config.state_file, logger)
        self.unifi_client = UniFiClient(config, logger)
        self.namecheap_client = NameCheapDDNSClient(config, logger)
        self.running = True
        self.require_confirmation = require_confirmation

    def check_and_update(self, skip_confirmation: bool = False) -> bool:
        """Check current IP and update DNS if changed."""
        try:
            # Get current WAN IP
            current_ip = self.unifi_client.get_wan_ip()

            if not current_ip:
                self.logger.error("Could not retrieve WAN IP")
                self.state_manager.increment_error()
                return False

            self.state_manager.update_check()

            # Check if IP has changed
            last_ip = self.state_manager.state.last_ip

            if current_ip == last_ip:
                self.logger.info(f"IP unchanged: {current_ip}")
                if not self.require_confirmation or skip_confirmation:
                    return True

            self.logger.info(f"IP changed: {last_ip} -> {current_ip}")

            # Update NameCheap DNS
            if self.namecheap_client.update_ip(current_ip):
                self.state_manager.update_ip(current_ip)
                return True
            else:
                self.state_manager.increment_error()
                return False

        except Exception as e:
            self.logger.error(f"Error in check_and_update: {e}")
            self.state_manager.increment_error()
            return False

    def run_daemon(self):
        """Run as a daemon, checking periodically."""
        self.logger.info(f"Starting DDNS updater daemon (check interval: {self.config.check_interval}s)")

        while self.running:
            try:
                # Skip confirmation in daemon mode
                self.check_and_update(skip_confirmation=True)

                # Sleep until next check
                time.sleep(self.config.check_interval)

            except KeyboardInterrupt:
                self.logger.info("Received keyboard interrupt, shutting down...")
                break
            except Exception as e:
                self.logger.error(f"Unexpected error in daemon loop: {e}")
                time.sleep(self.config.retry_delay)

        self.logger.info("DDNS updater daemon stopped")

    def get_status(self) -> Dict[str, Any]:
        """Get current application status."""
        return {
            'last_ip': self.state_manager.state.last_ip,
            'last_update': self.state_manager.state.last_update,
            'last_check': self.state_manager.state.last_check,
            'update_count': self.state_manager.state.update_count,
            'error_count': self.state_manager.state.error_count,
        }


# ============================================================================
# INTERACTIVE INTERFACE
# ============================================================================

class InteractiveDDNS:
    """Interactive menu-driven interface for DDNS updater."""

    def __init__(self):
        self.console = Console()
        self.config: Optional[Config] = None
        self.app: Optional[DDNSUpdater] = None
        self.logger = None

    def clear_screen(self):
        """Clear the console screen."""
        self.console.clear()

    def show_header(self):
        """Display application header."""
        header = Text()
        header.append("NameCheap Dynamic DNS Updater\n", style="bold cyan")
        header.append("UniFi Cloud API Integration", style="dim")

        panel = Panel(
            header,
            box=box.DOUBLE,
            border_style="cyan",
            padding=(1, 2)
        )
        self.console.print(panel)
        self.console.print()

    def load_config(self) -> bool:
        """Load configuration file."""
        config_path = "config.json"

        if not Path(config_path).exists():
            self.console.print(f"[yellow]Configuration file not found: {config_path}[/yellow]")
            create = Confirm.ask("Would you like to create a new configuration?")

            if create:
                return self.create_config()
            return False

        try:
            self.config = Config.from_file(config_path)
            self.logger = setup_logging(self.config.log_file, self.config.log_level, verbose=False)
            self.app = DDNSUpdater(self.config, self.logger, require_confirmation=False)

            self.console.print(f"[green]Configuration loaded successfully from {config_path}[/green]")
            return True
        except Exception as e:
            self.console.print(f"[red]Error loading configuration: {e}[/red]")
            return False

    def create_config(self) -> bool:
        """Interactive configuration creation."""
        self.console.print("\n[bold cyan]Configuration Setup[/bold cyan]\n")

        self.console.print("[yellow]UniFi Cloud API Settings[/yellow]")
        unifi_api_key = Prompt.ask("UniFi API Key", default="")

        self.console.print("\n[yellow]NameCheap Dynamic DNS Settings[/yellow]")
        namecheap_host = Prompt.ask("Subdomain (e.g., 'cameras')", default="")
        namecheap_domain = Prompt.ask("Domain (e.g., 'example.com')", default="")
        namecheap_password = Prompt.ask("Dynamic DNS Password", default="")

        self.console.print("\n[yellow]Application Settings[/yellow]")
        check_interval = Prompt.ask("Check interval (seconds)", default="300")

        config_data = {
            "unifi_host": "api.ui.com",
            "unifi_api_key": unifi_api_key,
            "namecheap_host": namecheap_host,
            "namecheap_domain": namecheap_domain,
            "namecheap_password": namecheap_password,
            "unifi_verify_ssl": True,
            "check_interval": int(check_interval),
            "state_file": "ddns_state.json",
            "log_file": "ddns_updater.log",
            "log_level": "INFO",
            "max_retries": 3,
            "retry_delay": 5
        }

        try:
            with open("config.json", "w") as f:
                json.dump(config_data, f, indent=2)

            self.console.print("\n[green]Configuration saved to config.json[/green]")
            return self.load_config()
        except Exception as e:
            self.console.print(f"\n[red]Error saving configuration: {e}[/red]")
            return False

    def show_current_status(self):
        """Display current status and configuration."""
        self.clear_screen()
        self.show_header()

        # Configuration Info
        config_table = Table(title="Current Configuration", box=box.ROUNDED, border_style="blue")
        config_table.add_column("Setting", style="cyan")
        config_table.add_column("Value", style="green")

        config_table.add_row("Domain", f"{self.config.namecheap_host}.{self.config.namecheap_domain}")
        config_table.add_row("Check Interval", f"{self.config.check_interval} seconds")
        config_table.add_row("Log Level", self.config.log_level)
        config_table.add_row("State File", self.config.state_file)

        self.console.print(config_table)
        self.console.print()

        # Status Info
        status = self.app.get_status()

        status_table = Table(title="Current Status", box=box.ROUNDED, border_style="green")
        status_table.add_column("Property", style="cyan")
        status_table.add_column("Value", style="yellow")

        status_table.add_row("Last Known IP", status['last_ip'] or "None")
        status_table.add_row("Last Update", status['last_update'] or "Never")
        status_table.add_row("Last Check", status['last_check'] or "Never")
        status_table.add_row("Update Count", str(status['update_count']))
        status_table.add_row("Error Count", str(status['error_count']))

        self.console.print(status_table)
        self.console.print()

    def check_wan_ip(self):
        """Check current WAN IP."""
        self.clear_screen()
        self.show_header()

        self.console.print("[bold cyan]Checking WAN IP from UniFi Cloud API...[/bold cyan]\n")

        try:
            with self.console.status("[bold green]Connecting to UniFi Cloud API...", spinner="dots"):
                ip = self.app.unifi_client.get_wan_ip()

            if ip:
                panel = Panel(
                    f"[bold green]{ip}[/bold green]",
                    title="Current WAN IP",
                    box=box.DOUBLE,
                    border_style="green",
                    padding=(1, 2)
                )
                self.console.print(panel)

                last_ip = self.app.state_manager.state.last_ip
                if last_ip:
                    if ip == last_ip:
                        self.console.print(f"\n[green]IP unchanged from last check: {last_ip}[/green]")
                    else:
                        self.console.print(f"\n[yellow]IP changed! Previous: {last_ip}[/yellow]")
            else:
                self.console.print("[red]Failed to retrieve WAN IP[/red]")

        except Exception as e:
            self.console.print(f"[red]Error: {e}[/red]")

        self.console.print()
        Prompt.ask("\nPress Enter to continue", default="")

    def update_dns(self, confirm: bool = True):
        """Update DNS record."""
        self.clear_screen()
        self.show_header()

        self.console.print("[bold cyan]DNS Update Process[/bold cyan]\n")

        try:
            # Get current IP
            with self.console.status("[bold green]Retrieving current WAN IP...", spinner="dots"):
                current_ip = self.app.unifi_client.get_wan_ip()

            if not current_ip:
                self.console.print("[red]Failed to retrieve WAN IP[/red]")
                Prompt.ask("\nPress Enter to continue", default="")
                return

            last_ip = self.app.state_manager.state.last_ip

            # Show info table
            info_table = Table(box=box.ROUNDED, border_style="cyan")
            info_table.add_column("Property", style="cyan")
            info_table.add_column("Value", style="yellow")

            info_table.add_row("Domain", f"{self.config.namecheap_host}.{self.config.namecheap_domain}")
            info_table.add_row("Current IP", current_ip)
            info_table.add_row("Last IP", last_ip or "None (first run)")
            info_table.add_row("Status", "IP Changed" if current_ip != last_ip else "No Change")

            self.console.print(info_table)
            self.console.print()

            # Confirm update
            if confirm:
                if current_ip == last_ip:
                    self.console.print("[yellow]IP address hasn't changed.[/yellow]")
                    proceed = Confirm.ask("Force update anyway?", default=False)
                else:
                    proceed = Confirm.ask("Proceed with DNS update?", default=True)

                if not proceed:
                    self.console.print("\n[yellow]Update cancelled[/yellow]")
                    Prompt.ask("\nPress Enter to continue", default="")
                    return

            # Perform update
            with self.console.status("[bold green]Updating NameCheap DNS...", spinner="dots"):
                success = self.app.namecheap_client.update_ip(current_ip)

            if success:
                self.app.state_manager.update_ip(current_ip)

                panel = Panel(
                    f"[bold green]DNS successfully updated to {current_ip}[/bold green]",
                    title="Success",
                    box=box.DOUBLE,
                    border_style="green"
                )
                self.console.print(panel)
            else:
                self.console.print("[red]DNS update failed[/red]")

        except Exception as e:
            self.console.print(f"[red]Error: {e}[/red]")

        self.console.print()
        Prompt.ask("\nPress Enter to continue", default="")

    def run_daemon_mode(self):
        """Run in daemon mode."""
        self.clear_screen()
        self.show_header()

        self.console.print("[bold yellow]WARNING: Daemon mode will run continuously![/bold yellow]")
        self.console.print(f"Check interval: {self.config.check_interval} seconds\n")

        proceed = Confirm.ask("Start daemon mode?", default=False)

        if not proceed:
            return

        self.console.print("\n[green]Starting daemon mode... Press Ctrl+C to stop[/green]\n")

        try:
            self.app.run_daemon()
        except KeyboardInterrupt:
            self.console.print("\n\n[yellow]Daemon stopped by user[/yellow]")
            Prompt.ask("\nPress Enter to continue", default="")

    def test_connections(self):
        """Test UniFi and NameCheap connections."""
        self.clear_screen()
        self.show_header()

        self.console.print("[bold cyan]Connection Tests[/bold cyan]\n")

        # Test UniFi
        self.console.print("[yellow]Testing UniFi Cloud API...[/yellow]")
        try:
            with self.console.status("[bold green]Connecting...", spinner="dots"):
                ip = self.app.unifi_client.get_wan_ip()

            if ip:
                self.console.print(f"[green]SUCCESS: UniFi API - WAN IP: {ip}[/green]")
            else:
                self.console.print("[red]ERROR: UniFi API - Failed to retrieve IP[/red]")
        except Exception as e:
            self.console.print(f"[red]ERROR: UniFi API - {e}[/red]")

        self.console.print()

        # Test NameCheap
        test_nc = Confirm.ask("Test NameCheap update? (will actually update DNS)", default=False)

        if test_nc:
            try:
                with self.console.status("[bold green]Testing NameCheap...", spinner="dots"):
                    ip = self.app.unifi_client.get_wan_ip()
                    if ip:
                        success = self.app.namecheap_client.update_ip(ip)

                if success:
                    self.console.print(f"[green]SUCCESS: NameCheap - Updated to {ip}[/green]")
                else:
                    self.console.print("[red]ERROR: NameCheap - Update failed[/red]")
            except Exception as e:
                self.console.print(f"[red]ERROR: NameCheap - {e}[/red]")

        self.console.print()
        Prompt.ask("\nPress Enter to continue", default="")

    def show_logs(self):
        """Display recent log entries."""
        self.clear_screen()
        self.show_header()

        log_file = Path(self.config.log_file)

        if not log_file.exists():
            self.console.print("[yellow]No log file found[/yellow]")
            Prompt.ask("\nPress Enter to continue", default="")
            return

        try:
            with open(log_file, 'r') as f:
                lines = f.readlines()

            # Show last 20 lines
            recent_lines = lines[-20:] if len(lines) > 20 else lines

            self.console.print("[bold cyan]Recent Log Entries (last 20)[/bold cyan]\n")

            for line in recent_lines:
                line = line.strip()
                if 'ERROR' in line:
                    self.console.print(f"[red]{line}[/red]")
                elif 'WARNING' in line:
                    self.console.print(f"[yellow]{line}[/yellow]")
                elif 'INFO' in line:
                    self.console.print(f"[green]{line}[/green]")
                else:
                    self.console.print(line)

        except Exception as e:
            self.console.print(f"[red]Error reading log file: {e}[/red]")

        self.console.print()
        Prompt.ask("\nPress Enter to continue", default="")

    def show_main_menu(self):
        """Display main menu and handle selection."""
        while True:
            self.clear_screen()
            self.show_header()

            menu_table = Table(box=box.ROUNDED, border_style="cyan", show_header=False)
            menu_table.add_column("Option", style="cyan bold", width=8)
            menu_table.add_column("Description", style="white")

            menu_table.add_row("1", "View Current Status")
            menu_table.add_row("2", "Check WAN IP")
            menu_table.add_row("3", "Update DNS (with confirmation)")
            menu_table.add_row("4", "Update DNS (force, no confirmation)")
            menu_table.add_row("5", "Run Daemon Mode")
            menu_table.add_row("6", "Test Connections")
            menu_table.add_row("7", "View Recent Logs")
            menu_table.add_row("8", "Reload Configuration")
            menu_table.add_row("0", "Exit")

            self.console.print(menu_table)
            self.console.print()

            choice = Prompt.ask("Select an option", choices=["0", "1", "2", "3", "4", "5", "6", "7", "8"])

            if choice == "0":
                self.console.print("\n[cyan]Goodbye![/cyan]\n")
                break
            elif choice == "1":
                self.show_current_status()
                Prompt.ask("\nPress Enter to continue", default="")
            elif choice == "2":
                self.check_wan_ip()
            elif choice == "3":
                self.update_dns(confirm=True)
            elif choice == "4":
                self.update_dns(confirm=False)
            elif choice == "5":
                self.run_daemon_mode()
            elif choice == "6":
                self.test_connections()
            elif choice == "7":
                self.show_logs()
            elif choice == "8":
                if self.load_config():
                    self.console.print("\n[green]Configuration reloaded[/green]")
                    Prompt.ask("\nPress Enter to continue", default="")

    def run(self):
        """Main application entry point."""
        try:
            self.clear_screen()
            self.show_header()

            # Load configuration
            if not self.load_config():
                self.console.print("\n[red]Failed to load configuration. Exiting.[/red]\n")
                return

            self.console.print()
            Prompt.ask("Press Enter to continue to main menu", default="")

            # Show main menu
            self.show_main_menu()

        except KeyboardInterrupt:
            self.console.print("\n\n[yellow]Interrupted by user[/yellow]\n")
        except Exception as e:
            self.console.print(f"\n[red]Unexpected error: {e}[/red]\n")


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Entry point."""
    app = InteractiveDDNS()
    app.run()


if __name__ == '__main__':
    main()
