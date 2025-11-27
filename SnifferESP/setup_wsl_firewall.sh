#!/bin/bash

echo "🔧 Configuring WSL Firewall for UDP 4242..."

# 1. Try UFW (Uncomplicated Firewall)
if command -v ufw >/dev/null 2>&1; then
    echo "   Found UFW, adding rule..."
    sudo ufw allow 4242/udp
    echo "   ✅ UFW rule added."
else
    echo "   ℹ️ UFW not found (skipping)."
fi

# 2. Try IPTables (Standard Linux Firewall)
if command -v iptables >/dev/null 2>&1; then
    echo "   Found iptables, adding rule..."
    # Accept input on UDP 4242
    sudo iptables -I INPUT -p udp --dport 4242 -j ACCEPT
    echo "   ✅ iptables rule added."
else
    echo "   ⚠️ iptables not found (unlikely in WSL)."
fi

echo ""
echo "🎉 Configuration complete!"
echo "Please try running 'nc -u -l -p 4242' again to verify."
