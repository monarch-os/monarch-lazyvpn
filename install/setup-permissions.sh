#!/bin/bash
# monarch-lazyvpn permission setup script
# Configures polkit or sudoers to allow VPN management without repeated password prompts
#
# Usage: sudo ./setup-permissions.sh [install|uninstall|status]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLKIT_RULES_SRC="$SCRIPT_DIR/50-monarch-lazyvpn.rules"
SUDOERS_SRC="$SCRIPT_DIR/monarch-lazyvpn.sudoers"

POLKIT_RULES_DEST="/usr/share/polkit-1/rules.d/50-monarch-lazyvpn.rules"
SUDOERS_DEST="/etc/sudoers.d/monarch-lazyvpn"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Detect polkit version and capabilities
detect_polkit() {
    if ! command -v pkexec &> /dev/null; then
        echo "none"
        return
    fi

    # Check for polkit rules.d directory (polkit >= 0.106)
    if [[ -d "/usr/share/polkit-1/rules.d" ]]; then
        # Verify polkitd supports JavaScript rules
        if command -v pkaction &> /dev/null; then
            local version
            version=$(pkaction --version 2>/dev/null | grep -oP '\d+\.\d+' | head -1 || echo "0.0")
            local major minor
            major=$(echo "$version" | cut -d. -f1)
            minor=$(echo "$version" | cut -d. -f2)
            
            # polkit >= 0.106 supports JavaScript rules
            if [[ "$major" -gt 0 ]] || [[ "$major" -eq 0 && "$minor" -ge 106 ]]; then
                echo "modern"
                return
            fi
        fi
        # Directory exists but version unknown, try modern
        echo "modern"
        return
    fi

    # Check for legacy pkla directory
    if [[ -d "/etc/polkit-1/localauthority" ]]; then
        echo "legacy"
        return
    fi

    echo "none"
}

# Check if user is in wheel or sudo group
check_user_groups() {
    local user="$1"
    if id -nG "$user" 2>/dev/null | grep -qwE "(wheel|sudo)"; then
        return 0
    fi
    return 1
}

# Install polkit rules (modern)
install_polkit_modern() {
    log_info "Installing polkit rules (modern)..."
    
    if [[ ! -f "$POLKIT_RULES_SRC" ]]; then
        log_error "Polkit rules file not found: $POLKIT_RULES_SRC"
        return 1
    fi

    cp "$POLKIT_RULES_SRC" "$POLKIT_RULES_DEST"
    chmod 644 "$POLKIT_RULES_DEST"
    chown root:root "$POLKIT_RULES_DEST"

    # Restart polkit to apply rules
    if systemctl is-active --quiet polkit; then
        systemctl restart polkit
        log_success "Polkit service restarted"
    fi

    log_success "Polkit rules installed to $POLKIT_RULES_DEST"
    return 0
}

# Install sudoers file
install_sudoers() {
    log_info "Installing sudoers configuration..."

    if [[ ! -f "$SUDOERS_SRC" ]]; then
        log_error "Sudoers file not found: $SUDOERS_SRC"
        return 1
    fi

    # Validate sudoers file syntax
    if ! visudo -c -f "$SUDOERS_SRC" &> /dev/null; then
        log_error "Sudoers file has syntax errors!"
        visudo -c -f "$SUDOERS_SRC"
        return 1
    fi

    cp "$SUDOERS_SRC" "$SUDOERS_DEST"
    chmod 440 "$SUDOERS_DEST"
    chown root:root "$SUDOERS_DEST"

    log_success "Sudoers configuration installed to $SUDOERS_DEST"
    return 0
}

# Uninstall polkit rules
uninstall_polkit() {
    if [[ -f "$POLKIT_RULES_DEST" ]]; then
        rm -f "$POLKIT_RULES_DEST"
        log_success "Removed polkit rules: $POLKIT_RULES_DEST"
        
        # Restart polkit
        if systemctl is-active --quiet polkit; then
            systemctl restart polkit
        fi
    else
        log_info "Polkit rules not installed (skipping)"
    fi
}

# Uninstall sudoers
uninstall_sudoers() {
    if [[ -f "$SUDOERS_DEST" ]]; then
        rm -f "$SUDOERS_DEST"
        log_success "Removed sudoers configuration: $SUDOERS_DEST"
    else
        log_info "Sudoers configuration not installed (skipping)"
    fi
}

# Show status
show_status() {
    echo ""
    echo "=== monarch-lazyvpn Permission Status ==="
    echo ""

    # Polkit status
    local polkit_type
    polkit_type=$(detect_polkit)
    
    echo "Polkit:"
    case "$polkit_type" in
        modern)
            echo "  Type: Modern (JavaScript rules)"
            if [[ -f "$POLKIT_RULES_DEST" ]]; then
                echo -e "  Rules: ${GREEN}Installed${NC}"
            else
                echo -e "  Rules: ${YELLOW}Not installed${NC}"
            fi
            ;;
        legacy)
            echo "  Type: Legacy (pkla)"
            echo -e "  Rules: ${YELLOW}Not supported (use sudoers)${NC}"
            ;;
        none)
            echo -e "  Type: ${YELLOW}Not available${NC}"
            ;;
    esac
    echo ""

    # Sudoers status
    echo "Sudoers:"
    if [[ -f "$SUDOERS_DEST" ]]; then
        echo -e "  Configuration: ${GREEN}Installed${NC}"
    else
        echo -e "  Configuration: ${YELLOW}Not installed${NC}"
    fi
    echo ""

    # Current user check
    local real_user="${SUDO_USER:-$USER}"
    echo "Current user: $real_user"
    if check_user_groups "$real_user"; then
        echo -e "  Group membership: ${GREEN}OK${NC} (in wheel or sudo group)"
    else
        echo -e "  Group membership: ${RED}MISSING${NC}"
        echo "  -> Add user to wheel or sudo group: sudo usermod -aG wheel $real_user"
    fi
    echo ""

    # Required commands
    echo "Required commands:"
    local cmds=("wg-quick" "nft" "sysctl" "ip")
    for cmd in "${cmds[@]}"; do
        if command -v "$cmd" &> /dev/null; then
            echo -e "  $cmd: ${GREEN}Found${NC} ($(command -v "$cmd"))"
        else
            echo -e "  $cmd: ${RED}Not found${NC}"
        fi
    done
    echo ""
}

# Main install function
do_install() {
    check_root

    local real_user="${SUDO_USER:-$USER}"
    log_info "Setting up permissions for monarch-lazyvpn..."
    echo ""

    # Check user group membership
    if ! check_user_groups "$real_user"; then
        log_warn "User '$real_user' is not in wheel or sudo group"
        log_warn "Permission rules will not apply until user is added to one of these groups"
        echo ""
        read -p "Add user to wheel group now? [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            usermod -aG wheel "$real_user"
            log_success "User '$real_user' added to wheel group"
            log_warn "User must log out and back in for group changes to take effect"
        fi
        echo ""
    fi

    # Detect and install appropriate permission system
    local polkit_type
    polkit_type=$(detect_polkit)
    local installed=false

    case "$polkit_type" in
        modern)
            log_info "Detected modern polkit (preferred)"
            if install_polkit_modern; then
                installed=true
            fi
            ;;
        legacy)
            log_warn "Detected legacy polkit (pkla) - not supported, using sudoers"
            ;;
        none)
            log_warn "Polkit not available, using sudoers"
            ;;
    esac

    # Install sudoers as fallback or primary
    if [[ "$installed" == false ]] || [[ "$polkit_type" != "modern" ]]; then
        if install_sudoers; then
            installed=true
        fi
    else
        # Also install sudoers as fallback for non-graphical sessions
        log_info "Installing sudoers as fallback for non-graphical sessions..."
        install_sudoers || true
    fi

    if [[ "$installed" == true ]]; then
        echo ""
        log_success "Permission setup complete!"
        echo ""
        echo "You can now use monarch-lazyvpn without repeated password prompts."
        echo "If you were added to a group, please log out and back in first."
    else
        log_error "Permission setup failed"
        exit 1
    fi
}

# Main uninstall function
do_uninstall() {
    check_root
    
    log_info "Removing monarch-lazyvpn permissions..."
    echo ""
    
    uninstall_polkit
    uninstall_sudoers
    
    echo ""
    log_success "Permission configuration removed"
}

# Print usage
usage() {
    echo "Usage: sudo $0 [command]"
    echo ""
    echo "Commands:"
    echo "  install     Install permission configuration (polkit + sudoers)"
    echo "  uninstall   Remove permission configuration"
    echo "  status      Show current permission status"
    echo "  help        Show this help message"
    echo ""
    echo "Examples:"
    echo "  sudo $0 install    # Setup permissions"
    echo "  sudo $0 status     # Check current status"
    echo "  sudo $0 uninstall  # Remove permissions"
}

# Main
case "${1:-install}" in
    install)
        do_install
        ;;
    uninstall|remove)
        do_uninstall
        ;;
    status|check)
        show_status
        ;;
    help|--help|-h)
        usage
        ;;
    *)
        log_error "Unknown command: $1"
        usage
        exit 1
        ;;
esac
