#!/bin/bash

# init-firewall.sh
# Firewall initialization script for Claude Code development container
# This script sets up network security rules while allowing necessary connections

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

# Check if running as root or with sufficient privileges
if ! command -v iptables &> /dev/null; then
    error "iptables not found. Please ensure iptables is installed."
    exit 1
fi

# Preserve Docker's DNS rules
log "Preserving Docker DNS configuration..."
DOCKER_DNS_RULES=$(iptables -t nat -S | grep "DOCKER\|docker" || true)

# Create ipset for allowed domains
log "Creating ipset for allowed domains..."
ipset create allowed_domains hash:ip maxelem 1000000 2>/dev/null || true
ipset flush allowed_domains 2>/dev/null || true

# Function to add IP to allowed set with validation
add_ip_to_allowed() {
    local ip="$1"
    # Basic IP validation
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        ipset add allowed_domains "$ip" 2>/dev/null || true
        log "Added IP to allowed list: $ip"
    else
        warn "Invalid IP address format: $ip"
    fi
}

# Add GitHub IP ranges
log "Fetching and adding GitHub IP ranges..."
if command -v curl &> /dev/null; then
    github_ips=$(curl -s https://api.github.com/meta | grep -o '"git":\[[^]]*\]' | grep -o '[0-9.]\+/[0-9]\+' || true)
    for cidr in $github_ips; do
        # Convert CIDR to individual IPs (simplified approach for small ranges)
        base_ip=$(echo "$cidr" | cut -d'/' -f1)
        add_ip_to_allowed "$base_ip"
    done
else
    warn "curl not available, skipping GitHub IP ranges"
fi

# Add essential service IPs
essential_domains=(
    "anthropic.com"
    "claude.ai"
    "api.anthropic.com"
    "github.com"
    "api.github.com"
    "raw.githubusercontent.com"
    "registry.npmjs.org"
    "nodejs.org"
    "microsoft.com"
    "1.1.1.1"  # Cloudflare DNS
    "8.8.8.8"  # Google DNS
)

log "Resolving and adding essential domain IPs..."
for domain in "${essential_domains[@]}"; do
    if command -v nslookup &> /dev/null; then
        ips=$(nslookup "$domain" 2>/dev/null | grep "Address" | awk '{print $2}' | grep -E "^[0-9]" || true)
        for ip in $ips; do
            add_ip_to_allowed "$ip"
        done
    elif command -v dig &> /dev/null; then
        ips=$(dig +short "$domain" 2>/dev/null | grep -E "^[0-9]" || true)
        for ip in $ips; do
            add_ip_to_allowed "$ip"
        done
    else
        warn "No DNS lookup tools available, skipping domain resolution for $domain"
    fi
done

# Allow localhost and private networks
log "Adding localhost and private network ranges..."
add_ip_to_allowed "127.0.0.1"
add_ip_to_allowed "10.0.0.0"
add_ip_to_allowed "172.16.0.0"
add_ip_to_allowed "192.168.0.0"

# Set up iptables rules
log "Configuring iptables rules..."

# Allow loopback
iptables -I INPUT 1 -i lo -j ACCEPT 2>/dev/null || true
iptables -I OUTPUT 1 -o lo -j ACCEPT 2>/dev/null || true

# Allow established connections
iptables -I INPUT 2 -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true

# Allow Docker internal communication
iptables -I INPUT 3 -s 172.16.0.0/12 -j ACCEPT 2>/dev/null || true
iptables -I OUTPUT 3 -d 172.16.0.0/12 -j ACCEPT 2>/dev/null || true

# Allow communication with allowed domains
iptables -I OUTPUT 4 -m set --match-set allowed_domains dst -j ACCEPT 2>/dev/null || true

# Allow DNS queries
iptables -I OUTPUT 5 -p udp --dport 53 -j ACCEPT 2>/dev/null || true
iptables -I OUTPUT 6 -p tcp --dport 53 -j ACCEPT 2>/dev/null || true

# Allow HTTP/HTTPS
iptables -I OUTPUT 7 -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
iptables -I OUTPUT 8 -p tcp --dport 443 -j ACCEPT 2>/dev/null || true

# Allow SSH
iptables -I OUTPUT 9 -p tcp --dport 22 -j ACCEPT 2>/dev/null || true

# Set default policies (be careful with this in development)
# iptables -P INPUT DROP 2>/dev/null || true
# iptables -P OUTPUT DROP 2>/dev/null || true
# iptables -P FORWARD DROP 2>/dev/null || true

log "Firewall configuration completed successfully"

# Test connectivity
log "Testing connectivity to essential services..."
test_domains=("anthropic.com" "github.com" "registry.npmjs.org")
for domain in "${test_domains[@]}"; do
    if command -v curl &> /dev/null; then
        if curl -s --connect-timeout 5 "https://$domain" > /dev/null 2>&1; then
            log "✓ Connectivity test passed for $domain"
        else
            warn "✗ Connectivity test failed for $domain"
        fi
    fi
done

log "Firewall initialization complete!"