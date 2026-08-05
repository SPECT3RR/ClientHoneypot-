# Block the Docker subnet from reaching Windows host services.
#
# WHY THIS EXISTS
# ---------------
# A hunting container renders attacker-controlled content. It is hardened
# (cap-drop ALL, non-root, no-new-privileges) and it runs inside the WSL2 VM,
# so reaching Windows needs a chain of escapes. But Docker Desktop injects
# host.docker.internal into every container and proxies it to host loopback
# services, so the route exists whether or not --add-host is passed.
#
# Measured from inside a hunt container before this rule:
#
#     host:8000 (dashboard) -> CONNECTED
#     host:8001 (decoy)     -> CONNECTED
#     host:445  (SMB)       -> CONNECTED     <-- the one that matters
#     host:3389 (RDP)       -> refused
#     host:22   (SSH)       -> refused
#
# SMB on 445 is Windows file sharing. A session that achieved code execution
# in the container could attempt it against the host. This closes that.
#
# REQUIRES ADMINISTRATOR.
#
#   .\scripts\harden_firewall.ps1            # apply
#   .\scripts\harden_firewall.ps1 -Remove    # undo
#   .\scripts\harden_firewall.ps1 -WhatIf    # show without changing anything

param(
    [switch]$Remove,
    [switch]$WhatIf
)

$RuleGroup = "ClientHoneypot containment"

# Docker Desktop's host network on Windows. host.docker.internal resolved to
# 192.168.65.254 on this machine; the whole /24 is Docker's.
$DockerSubnets = @("192.168.65.0/24", "172.16.0.0/12")

# Ports a hunted session has no business reaching on the host.
#   445/139/135  SMB and RPC — lateral movement and file access
#   3389         RDP
#   5985/5986    WinRM — remote command execution
#   8000         the dashboard itself: it can clear verdicts and read the
#                canary vault, so a compromised hunter must not reach it
$BlockedPorts = @(135, 139, 445, 3389, 5985, 5986, 8000)

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Output "This needs Administrator. Re-run from an elevated PowerShell."
        exit 1
    }
}

if ($Remove) {
    Assert-Admin
    $existing = Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue
    if (-not $existing) { Write-Output "No rules to remove."; exit 0 }
    $existing | Remove-NetFirewallRule
    Write-Output "Removed $($existing.Count) rule(s) in group '$RuleGroup'."
    exit 0
}

Write-Output "Docker subnets : $($DockerSubnets -join ', ')"
Write-Output "Blocked ports  : $($BlockedPorts -join ', ')"
Write-Output ""

if ($WhatIf) {
    Write-Output "WhatIf — would create these inbound block rules:"
    foreach ($p in $BlockedPorts) {
        Write-Output "  block TCP/$p from $($DockerSubnets -join ',')"
    }
    Write-Output ""
    Write-Output "Nothing changed. Re-run without -WhatIf to apply."
    exit 0
}

Assert-Admin

# Replace rather than duplicate on re-run.
Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue

$created = 0
foreach ($port in $BlockedPorts) {
    try {
        New-NetFirewallRule `
            -DisplayName "Block Docker subnet -> host TCP/$port" `
            -Group $RuleGroup `
            -Direction Inbound `
            -Action Block `
            -Protocol TCP `
            -LocalPort $port `
            -RemoteAddress $DockerSubnets `
            -Profile Any `
            -Enabled True `
            -ErrorAction Stop | Out-Null
        Write-Output "  blocked TCP/$port"
        $created++
    } catch {
        Write-Output "  FAILED TCP/${port}: $($_.Exception.Message)"
    }
}

Write-Output ""
Write-Output "Created $created rule(s) in group '$RuleGroup'."
Write-Output ""
Write-Output "Verify from a container:"
Write-Output '  docker run --rm --network hunt_net --entrypoint python clienthoneypot/hunter:latest -c "import socket
for p in (445,3389,8000):
    try:
        socket.create_connection((''host.docker.internal'',p),timeout=3).close(); print(p,''REACHABLE'')
    except Exception: print(p,''blocked'')"'
Write-Output ""
Write-Output "This does NOT block the decoy on decoy_net — hunters reach it by"
Write-Output "container DNS, which never traverses the host."
