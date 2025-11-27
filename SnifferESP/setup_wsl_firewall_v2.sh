#!/bin/bash

echo "🔧 Configuring WSL Firewall (NFTables) for UDP 4242..."

# Check for root
if [ "$EUID" -ne 0 ]; then
  echo "❌ Please run as root (use sudo)."
  exit 1
fi

# Try NFTables
if command -v nft >/dev/null 2>&1; then
    echo "   Found nftables, adding rule..."

    # Create table if not exists
    nft add table inet filter

    # Create chain if not exists
    nft add chain inet filter input { type filter hook input priority 0 \; }

    # Add rule
    nft add rule inet filter input udp dport 4242 accept

    echo "   ✅ nftables rule added."
    echo "   Current rules:"
    nft list ruleset
else
    echo "   ⚠️ nftables not found."
    echo "   Trying to install iptables..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update && apt-get install -y iptables
        echo "   ✅ iptables installed. Please run the previous script again."
    else
        echo "   ❌ Could not install iptables. Please install it manually."
    fi
fi
