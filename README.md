# monarch-lazyvpn

A TUI (Terminal User Interface) WireGuard VPN manager for Linux with multi-provider support.

## Features

- **Multi-provider support**: ProtonVPN, custom WireGuard configs
- **TUI interface**: Navigate and connect with keyboard shortcuts
- **Killswitch**: nftables-based traffic blocking when VPN disconnects unexpectedly
- **Split-tunnel detection**: Identifies configs that don't route all traffic
- **Waybar integration**: Status output for i3/Sway status bars
- **Secure credential storage**: System keyring with encrypted fallback
- **Autonomous state detection**: Detects VPN state from system, not just config files

## Installation

### Build from source

```bash
cargo build --release
```

Binaries are created at:
- `target/release/monarch-lazyvpn` - Main TUI application
- `target/release/monarch-lazyvpn-status` - Status binary for Waybar/scripts

### Setup permissions

The VPN manager requires elevated privileges for WireGuard and firewall operations. Run the setup script to configure polkit/sudoers:

```bash
sudo ./install/setup-permissions.sh install
```

This allows VPN operations without repeated password prompts for users in the `wheel` or `sudo` group.

## Usage

### Main application

```bash
monarch-lazyvpn
```

### Keyboard shortcuts

| Key | Action |
|-----|--------|
| `j` / `↓` | Move down |
| `k` / `↑` | Move up |
| `Enter` / `l` | Connect to server / Expand provider |
| `h` | Collapse provider |
| `d` | Disconnect |
| `r` | Refresh server list |
| `K` | Toggle killswitch |
| `f` | Toggle favorite |
| `/` | Search |
| `i` | Import config |
| `q` | Quit |

### Status binary

For Waybar or other status bars:

```bash
# JSON output (default)
monarch-lazyvpn-status

# Waybar format
monarch-lazyvpn-status --format=waybar

# Plain text
monarch-lazyvpn-status --format=text
```

### Waybar configuration

Add to your Waybar config:

```json
"custom/vpn": {
    "exec": "monarch-lazyvpn-status --format=waybar",
    "return-type": "json",
    "interval": 5
}
```

## Configuration

Configuration is stored in `~/.config/monarch-lazyvpn/`:

- `config.toml` - Application settings
- `.connection_state` - Persistent connection state
- `custom-configs/` - Custom WireGuard configuration files

### config.toml options

```toml
# Enable killswitch by default
killswitch_enabled = true

# Allow LAN traffic when killswitch is active
killswitch_allow_lan = true

# Keep VPN running on exit (don't disconnect)
keep_vpn_on_exit = true

# Server list display mode: "all", "favorites", "country"
server_list_mode = "all"

# Favorite servers
favorites = ["server-id-1", "server-id-2"]

# Configured providers
configured_providers = ["protonvpn", "custom"]
```

## Providers

### ProtonVPN

1. Launch `monarch-lazyvpn`
2. Press `i` to import
3. Select "ProtonVPN"
4. Paste your WireGuard private key (from ProtonVPN account settings)

### Custom WireGuard configs

1. Press `i` to import
2. Select "Custom Config"
3. Navigate to your `.conf` file

Or manually place `.conf` files in `~/.config/monarch-lazyvpn/custom-configs/`

## Architecture

```
monarch-lazyvpn/
├── src/
│   ├── main.rs              # Entry point
│   ├── app.rs               # Application state and logic
│   ├── core/
│   │   ├── config.rs        # Configuration management
│   │   ├── connection.rs    # Connection state machine
│   │   ├── server.rs        # Server data structures
│   │   ├── provider/        # VPN provider implementations
│   │   └── error.rs         # Error types
│   ├── system/
│   │   ├── wireguard.rs     # WireGuard interface management
│   │   ├── firewall.rs      # nftables killswitch
│   │   ├── keyring.rs       # Credential storage
│   │   └── network.rs       # Network statistics
│   ├── tui/
│   │   ├── ui.rs            # UI rendering
│   │   ├── events.rs        # Keyboard event handling
│   │   └── widgets/         # UI components
│   ├── utils/
│   │   └── gluetun.rs       # Server list fetching
│   └── bin/
│       └── monarch-lazyvpn-status.rs  # Status binary
└── install/
    ├── setup-permissions.sh     # Permission setup script
    ├── 50-monarch-lazyvpn.rules # Polkit rules
    └── monarch-lazyvpn.sudoers  # Sudoers config
```

## Requirements

- Linux with WireGuard support
- `wg-quick` (wireguard-tools)
- `nft` (nftables) for killswitch
- Rust 1.70+ (for building)

## License

MIT
