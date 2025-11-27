# Check for Administrator privileges
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script requires Administrator privileges."
    Write-Warning "Please run as Administrator."
    exit 1
}

$RuleName = "ESP32_Sniffer_UDP_4242"
$Port = 4242

# Remove existing rule
Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule

# Create new rule
New-NetFirewallRule -DisplayName $RuleName `
                    -Direction Inbound `
                    -LocalPort $Port `
                    -Protocol UDP `
                    -Action Allow `
                    -Profile Any `
                    -Description "Allows inbound UDP traffic on port 4242"

Write-Host "Firewall rule created successfully." -ForegroundColor Green
Write-Host "Port: $Port (UDP)"

# Get current IP addresses
Write-Host ""
Write-Host "Current IP Addresses:" -ForegroundColor Cyan
$ips = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
    $_.InterfaceAlias -notlike '*Loopback*' -and $_.InterfaceAlias -notlike '*vEthernet*'
}
$ips | Select-Object IPAddress, InterfaceAlias | Format-Table -AutoSize
