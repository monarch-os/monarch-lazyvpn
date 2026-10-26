# monarch-lazyvpn

A native graphical WireGuard VPN manager for Linux, with headless CLI commands.

## Features

- **Multi-provider support**: ProtonVPN, custom WireGuard configs
- **GPUI interface**: Compact two-pane layout, embedded SVG flags, virtualized server list and keyboard navigation
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
- `target/release/monarch-lazyvpn` - Graphical application and CLI commands
- `target/release/monarch-lazyvpn-gui` - Compatibility launcher for the graphical application
- `target/release/monarch-lazyvpn-status` - Status binary for Waybar/scripts

### Setup permissions

The VPN manager requires elevated privileges for WireGuard and firewall operations. Run the setup script to configure polkit/sudoers:

```bash
sudo ./install/setup-permissions.sh install
```

This allows VPN operations without repeated password prompts for users in the `wheel` or `sudo` group.

### Graphical interface

On Monarch, `monarch install lazyvpn` installs the package, the **Mod+Ctrl+V**
shortcut, an 880 × 540 floating Niri window rule and the Noctalia palette template.
The package owns the desktop launcher and template; Monarch owns the per-user
integration. Existing installations are updated by `monarch reconcile` once
LazyVPN 0.2.0 or newer is installed. Removing it through `monarch remove lazyvpn`
keeps profiles and credentials.

```bash
cargo build --release --bin monarch-lazyvpn
target/release/monarch-lazyvpn --preview
target/release/monarch-lazyvpn
```

`--preview` uses in-memory sample profiles. It does not load credentials, write
VPN settings, or run network/firewall operations. Without it, the GUI uses the
existing configuration, credentials and connection engine. Only one
interactive instance can run at a time.

Launching either GUI binary again focuses the existing window on Niri. The
activation socket is private to your user; a second launch never starts another
VPN worker. Other compositors report that the existing window must be selected
manually. Preview windows use a separate instance lock.

The GUI and CLI commands share an OS lock under
`$XDG_RUNTIME_DIR/monarch-lazyvpn` (default: `/run/user/<uid>/monarch-lazyvpn`).
Crashes release the lock automatically. Do not delete `instance.lock` while the
application is running. `status` and `monarch-lazyvpn-status` remain available
without taking ownership; other CLI commands require closing the GUI first.
An older running version must be closed once after upgrading.

Connection snapshots are replaced atomically with private file permissions.
Reopening after a crash or closing with `keep_vpn_on_exit` enabled uses the
existing recovery path, without treating a reused PID as a running instance.

The GUI supports importing `.conf` files through the desktop file picker,
connecting, switching and disconnecting, searching, favorites, provider groups,
refreshing servers, and editing/renaming/deleting personal profiles. Custom-profile
actions appear directly below Connect, with deletion highlighted in red. The editor
validates WireGuard fields and keeps the stored private key when its replacement
field is blank. Disconnect the selected profile before modifying it. ProtonVPN imports
populate its server catalog; other WireGuard files remain personal profiles.
Encrypted credential fallback prompts appear inside the window.

At startup, the GUI displays saved servers and local profiles immediately.
Expired or incomplete server lists refresh in the background; cached profiles
remain usable if the network is unavailable. A failed update keeps the previous
list and reports the error. Closing the window cancels the refresh, and repeated
refresh requests share the current task. CLI commands still wait for their
server list before returning.

Use `j`/`k` or Up/Down to select a server or provider category. Left/`h` folds
the current category and keeps it selected; Right/`l` opens it, then enters its
first server when pressed again. `Enter` toggles a category or connects/disconnects,
`f` for favorites, `/` to focus search, `i` to import, `r` to refresh and `?` for
help. Escape returns focus from the search field to the list. Mouse and Tab
navigation are also supported.

Protection preferences apply at connection time and are editable while
disconnected. The active kill-switch state is displayed separately; split
tunnels do not enable it. Closing the window respects `keep_vpn_on_exit` and
waits for any pending transition to finish before shutting down the worker.

To install the GUI and its desktop launcher for the current user:

```bash
bash install/setup-gui.sh
```

This installs into `~/.local/bin` (which must be on your launcher PATH). On
Noctalia systems it also registers the data-only template in
`assets/noctalia/lazyvpn.json`, through a dedicated `noctalia/lazyvpn.toml`
overlay. Noctalia generates `~/.config/monarch-lazyvpn/theme.json`; the GUI
reloads it live, including dark/light changes. XDG config/data directories are
honored. Without a generated palette, the GUI uses the Monarch dark palette.
An existing Noctalia overlay is backed up as `lazyvpn.toml.bak`.

Build requirements include a current Rust toolchain and the GPUI Linux
dependencies (`wayland`, `libxkbcommon`, `libxkbcommon-x11`, `libxcb`,
`fontconfig`, `freetype2`, OpenSSL and a working graphics driver). Native file
selection uses the desktop portal. The default build includes GPUI through the
`gui` feature. `cargo build --release --no-default-features` builds only the
headless CLI and status binary; it has no interactive terminal interface.

GUI-focused checks: `cargo test --features gui --lib gui::`.

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
| `Enter` | Connect/disconnect or toggle category |
| `l` / `→` | Expand category or enter its first server |
| `h` / `←` | Collapse category |
| `d` | Disconnect |
| `r` | Refresh server list |
| `f` | Toggle favorite |
| `/` | Search |
| `i` | Import config |
| `?` | Show keyboard help |
| `Esc` | Close dialog or return focus to the list |
| `q` | Quit |

Custom profiles have visible Edit, Rename and Delete buttons. Protection
preferences are available in the right panel.

### Headless CLI

Subcommands do not open a window and work without a graphical session:

```bash
monarch-lazyvpn status --help
monarch-lazyvpn --format json status
monarch-lazyvpn list-servers --country FR
monarch-lazyvpn import profile.conf
monarch-lazyvpn connect SERVER_ID
monarch-lazyvpn disconnect
```

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
- `servers/` - Custom WireGuard configuration files

### config.toml options

```toml
# Enable killswitch by default
killswitch_enabled = true

# Allow LAN traffic when killswitch is active
killswitch_allow_lan = true

# Keep VPN running on exit (don't disconnect)
keep_vpn_on_exit = true

# Favorite servers
favorites = ["server-id-1", "server-id-2"]

# Configured providers
configured_providers = ["protonvpn", "custom"]
```

## Providers

### ProtonVPN

1. Launch `monarch-lazyvpn`
2. Press `i` to import
3. Choose a WireGuard `.conf` file downloaded from your ProtonVPN account
4. Confirm the import; the provider is detected automatically

### Custom WireGuard configs

1. Press `i` to import
2. Choose your `.conf` file
3. Confirm the import; private keys are stored separately from the profile

#### Renaming a custom config

1. Select the custom config in the server list
2. Click **Rename** below the connection button
3. Edit the name and click **Confirm** (`Esc` to cancel)

This renames the stored config file and moves its credentials and favorite entry
to the new name. You cannot rename a config while connected to it — disconnect first.

#### Deleting a custom config

1. Select the custom config in the server list
2. Click **Delete** below the connection button
3. Click **Confirm** in the confirmation panel

This removes the stored config file, its credentials from the keyring, and any
favorite entry. You cannot delete a config while connected to it — disconnect first.

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
│   ├── gui/
│   │   ├── view.rs          # GPUI rendering and keyboard navigation
│   │   ├── engine.rs        # Background VPN worker
│   │   ├── editor.rs        # Custom-profile validation and persistence
│   │   └── theme.rs         # Live Noctalia palette
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
- A current Rust toolchain and the GPUI dependencies listed above

## License

MIT
