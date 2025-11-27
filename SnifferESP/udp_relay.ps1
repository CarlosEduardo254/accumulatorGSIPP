# Get WSL IP Address (Just for logging)
Write-Host "Detecting WSL IP..."
try {
    $wslOutput = wsl ip addr
    $wslIP = $wslOutput | Select-String -Pattern "inet (\d+\.\d+\.\d+\.\d+)" | ForEach-Object { $_.Matches.Groups[1].Value } | Where-Object { $_ -ne "127.0.0.1" -and $_ -ne "10.255.255.254" } | Select-Object -First 1
} catch {
    $wslIP = "Unknown"
}

Write-Host "WSL IP detected: $wslIP" -ForegroundColor Cyan

$Port = 4242
$ListenIP = "192.168.137.1"
$TargetIP = "::1" # IPv6 Loopback

Write-Host "Starting UDP Relay (Hotspot -> IPv6 Loopback)..."
Write-Host "   Listening on: $ListenIP`:$Port"
Write-Host "   Forwarding to: [$TargetIP]:$Port"
Write-Host "   Press Ctrl+C to stop." -ForegroundColor Yellow

# 1. Receiver Client (Binds to Hotspot IP - IPv4)
$ReceiverClient = New-Object System.Net.Sockets.UdpClient
$LocalEndpoint = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Parse($ListenIP), $Port)
$ReceiverClient.Client.Bind($LocalEndpoint)

# 2. Sender Client (IPv6 for Localhost)
$SenderClient = New-Object System.Net.Sockets.UdpClient -ArgumentList ([System.Net.Sockets.AddressFamily]::InterNetworkV6)

# Target Endpoint (IPv6 Localhost)
$TargetEndpoint = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Parse($TargetIP), $Port)

# Source Endpoint for Receive (Any sender)
$RemoteEndpoint = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Any, 0)

try {
    while ($true) {
        # Receive packet
        $Data = $ReceiverClient.Receive([ref]$RemoteEndpoint)

        # Forward using the Sender Client
        $BytesSent = $SenderClient.Send($Data, $Data.Length, $TargetEndpoint)

        # Visual feedback
        Write-Host "." -NoNewline -ForegroundColor DarkGray
    }
}
catch {
    Write-Error $_.Exception.Message
}
finally {
    $ReceiverClient.Close()
    $SenderClient.Close()
    Write-Host ""
    Write-Host "Relay stopped."
}
