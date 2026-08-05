# Restart the RBI stack that was paused to free RAM for a hunting run.
#
# The containers were stopped, never removed, so this brings back the exact
# same containers with their volumes and state. Images were never touched.
#
#   .\scripts\resume_rbi.ps1

$list = Join-Path $PSScriptRoot ".rbi_paused_containers.txt"
if (-not (Test-Path $list)) {
    Write-Output "No paused-container record at $list -- nothing to resume."
    exit 0
}

$names = Get-Content $list | Where-Object { $_.Trim() }
Write-Output "Resuming $($names.Count) container(s)..."

# Start in reverse stop order so dependencies (db, clamav) come up first.
[array]::Reverse($names)
foreach ($n in $names) {
    docker start $n 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) { Write-Output "  started $n" }
    else { Write-Output "  FAILED  $n" }
}

Write-Output ""
docker ps --filter "label=com.docker.compose.project=rbi-final" --format "{{.Names}}  {{.Status}}"
