#!/bin/bash
# DuckDNS Setup for CloudDecept
# Run this on your Oracle Cloud VM after deployment

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

echo "=========================================="
echo "  DuckDNS Setup for CloudDecept"
echo "=========================================="
echo ""

# Get user input
read -p "Enter your DuckDNS subdomain (e.g., myhoneypot): " SUBDOMAIN
read -p "Enter your DuckDNS token (from duckdns.org): " TOKEN

if [ -z "$SUBDOMAIN" ] || [ -z "$TOKEN" ]; then
    log_error "Subdomain and token are required"
    exit 1
fi

FULL_DOMAIN="${SUBDOMAIN}.duckdns.org"

# Create update script
log_info "Creating DuckDNS update script..."
cat > ~/update-duckdns.sh << EOF
#!/bin/bash
# DuckDNS auto-update script for CloudDecept

DOMAIN="${SUBDOMAIN}"
TOKEN="${TOKEN}"
LOG_FILE="~/duckdns.log"

# Get current public IP
CURRENT_IP=\$(curl -s https://api.ipify.org)

# Update DuckDNS
RESPONSE=\$(curl -s "https://www.duckdns.org/update?domains=\${DOMAIN}&token=\${TOKEN}&ip=\${CURRENT_IP}&verbose=true")

# Log result
DATE=\$(date '+%Y-%m-%d %H:%M:%S')
echo "[\${DATE}] DuckDNS Update: \${RESPONSE} (IP: \${CURRENT_IP})" >> \${LOG_FILE}

# Check if successful
if [[ "\${RESPONSE}" == "OK"* ]]; then
    echo "[\${DATE}] SUCCESS: Updated \${DOMAIN}.duckdns.org to \${CURRENT_IP}" >> \${LOG_FILE}
else
    echo "[\${DATE}] ERROR: Failed to update DuckDNS: \${RESPONSE}" >> \${LOG_FILE}
fi
EOF

chmod +x ~/update-duckdns.sh
log_success "Update script created at ~/update-duckdns.sh"

# Test the update
log_info "Testing DuckDNS update..."
~/update-duckdns.sh
sleep 2
cat ~/duckdns.log

# Add to crontab
log_info "Adding to crontab (every 5 minutes)..."
(crontab -l 2>/dev/null | grep -v "update-duckdns"; echo "*/5 * * * * ~/update-duckdns.sh") | crontab -

log_success "DuckDNS configured!"
echo ""
echo "Your honeypot will be accessible at:"
echo "  SSH:  ssh -p 2222 ubuntu@${FULL_DOMAIN}"
echo "  Dashboard: http://${FULL_DOMAIN}:3000"
echo "  Cloud API: http://${FULL_DOMAIN}:8080"
echo ""
echo "To verify it's working:"
echo "  nslookup ${FULL_DOMAIN}"
echo "  curl http://${FULL_DOMAIN}:8080/health"
echo ""
echo "Logs: ~/duckdns.log"
echo "Crontab: crontab -l"