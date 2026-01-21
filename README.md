# HostWatch

A network monitoring application written in Rust that captures ARP and NDP packets to discover and track hosts on your network.

## Features

- **Packet Capture**: Uses libpcap to capture ARP and NDP packets with minimal overhead
- **Host Discovery**: Automatically discovers hosts through ARP requests/replies and IPv6 Neighbor Discovery
- **Persistent Storage**: Stores host information in SQLite database
- **Real-time Monitoring**: Continuously monitors network traffic for new hosts
- **Cross-platform**: Works on Linux, macOS, and Windows
## Requirements

- Rust 1.70 or later
- libpcap development libraries
- Root/Administrator privileges (for packet capture)

## Project Structure

```
hostwatch/
├── src/
│   ├── main.rs          # CLI entry point with argument parsing
│   ├── lib.rs           # Core HostWatch functionality
│   ├── database.rs      # SQLite database operations
├── Cargo.toml           # Dependencies and project configuration
├── Makefile             # Build and run commands
├── README.md            # Comprehensive documentation
```

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd hostwatch
```

2. Build the application:
```bash
cargo build --release
```

3. Run with root privileges:
```bash
sudo ./target/release/hostwatch -f
```

## Usage

### Basic Usage

Monitor all network interfaces:
```bash
sudo ./target/release/hostwatch -f
```

Monitor a specific interface:
```bash
sudo ./target/release/hostwatch -i en0 -f
```

Use a custom database file:
```bash
sudo ./target/release/hostwatch -d /path/to/hosts.db -f
```

Enable verbose logging:
```bash
sudo ./target/release/hostwatch -v -f
```

### Command Line Options

```
Usage: hostwatch [OPTIONS]

Options:
  -i, --interface <INTERFACE>
          Network interface to monitor [default: any]
  -s, --skip-nets <SKIP_NETS>
          Networks to ignore
  -d, --database <DATABASE>
          Database file path [default: hosts.db]
  -o, --oui-path <OUI_PATH>
          Path to oui.csv source file [default: /usr/local/opnsense/contrib/ieee/oui.csv]
  -p, --promisc
          Disable promiscuous mode
  -v, --verbose
          Verbose output
  -P, --pid-file <PID_FILE>
          PID file
  -u, --user <USER>
          Username to use after startup
  -g, --group <GROUP>
          Groupname to use after startup
  -U, --umask <UMASK>
          Umask of the PID file [default: 027]
  -c, --chown-pid-file
          Chown the PID file
  -w, --working-directory <WORKING_DIRECTORY>
          Working dir [default: /tmp]
  -S, --syslog
          Send output to syslog
  -f, --foreground
          do not daemonize, run in foreground
  -h, --help
          Print help
  -V, --version
          Print version
```

## How It Works

HostWatch uses the following packet filter to minimize overhead:
```
((arp && not src 0) || (icmp6 && (icmp6[icmp6type] == icmp6-neighborsolicit || icmp6[icmp6type] == icmp6-neighboradvert)))
```

This filter captures:
- ARP packets (excluding those with source address 0.0.0.0)
- IPv6 Neighbor Solicitation and Neighbor Advertisement packets

### Database Schema

The application stores the following information for each discovered host:

- **Ether Address**: Hardware address (for Ethernet hosts)
- **IP Address**: IPv4/IPv6 address
- **First Seen**: Timestamp when the host was first discovered
- **Last Seen**: Timestamp when the host was last seen


## Security Note

This application requires root/administrator privileges to capture network packets in the most effective way. 
Only run it on networks you own or have permission to monitor.


