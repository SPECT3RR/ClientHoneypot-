# Stop only OUR services, by identifying the process, never by port owner.
#
# A blind "kill whatever holds port 8000" loop is dangerous on a machine
# running anything else: Docker Desktop proxies host ports, so that loop can
# kill a Docker backend process and take the whole daemon (and every other
# project's containers) down with it. That happened once; hence this file.

$ourScripts = @('decoy_app/app.py', 'dashboard/app.py',
                'tests/mock_malicious_site.py', 'src/v2_orchestrator.py')

$killed = 0
Get-CimInstance Win32_Process -Filter "Name = 'python.exe'" | ForEach-Object {
    $cmd = $_.CommandLine
    if (-not $cmd) { return }
    foreach ($s in $ourScripts) {
        if ($cmd -replace '\\', '/' -like "*$s*") {
            Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
            $killed++
            break
        }
    }
}
Write-Output "stopped $killed ClientHoneypot service process(es)"
