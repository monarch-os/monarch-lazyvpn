#!/bin/bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
binary=${1:-$root/target/release/monarch-lazyvpn}
data=${XDG_DATA_HOME:-$HOME/.local/share}
config=${XDG_CONFIG_HOME:-$HOME/.config}

if [[ ! -x $binary ]]; then
  echo "Build first: cargo build --release --bin monarch-lazyvpn" >&2
  exit 1
fi

install -Dm755 "$binary" "$HOME/.local/bin/monarch-lazyvpn"
install -Dm644 "$root/assets/monarch-lazyvpn.desktop" "$data/applications/monarch-lazyvpn.desktop"

if command -v noctalia >/dev/null 2>&1; then
  install -Dm644 "$root/assets/noctalia/lazyvpn.json" "$data/monarch-lazyvpn/noctalia/lazyvpn.json"
  mkdir -p "$config/noctalia" "$config/monarch-lazyvpn"
  overlay="$config/noctalia/lazyvpn.toml"
  if [[ -f $overlay ]]; then
    cp -- "$overlay" "$overlay.bak"
  fi
  # TOML literal strings preserve spaces and backslashes in XDG paths.
  if [[ $data == *"'"* || $config == *"'"* ]]; then
    echo "Noctalia setup requires paths without single quotes; configure the template manually." >&2
    exit 1
  fi
  cat > "$overlay" <<EOF
[theme.templates.user.lazyvpn]
enabled = true
input_path = '$data/monarch-lazyvpn/noctalia/lazyvpn.json'
output_path = '$config/monarch-lazyvpn/theme.json'
EOF
  noctalia msg templates-apply || echo "Apply Noctalia templates once the shell is running." >&2
fi

echo "Installed LazyVPN in $HOME/.local/bin/monarch-lazyvpn"
