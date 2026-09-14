[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'
$serviceName = 'GamePathService'

Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service) {
    $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(15))
}
& sc.exe stop WinDivert | Out-Null
& sc.exe delete WinDivert | Out-Null

# Remove only routes attached to GamePath-created interfaces.
$interfaceIndexes = @(Get-NetAdapter -Name 'GamePath*' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ifIndex)
if ($interfaceIndexes.Count) {
    Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceIndex -in $interfaceIndexes } |
        Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
}

# Stop engines installed by GamePath or copied into its private temporary folder.
$nativeProgramFiles = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }
$programRuntime = Join-Path $nativeProgramFiles 'GamePath'
$legacyProgramRuntime = if (${env:ProgramFiles(x86)}) { Join-Path ${env:ProgramFiles(x86)} 'GamePath' } else { $null }
$temporaryRuntime = Join-Path $env:TEMP 'GamePath'
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Name -like 'gamepath-engine*.exe' -and
        ($_.ExecutablePath -like "$programRuntime\*" -or ($legacyProgramRuntime -and $_.ExecutablePath -like "$legacyProgramRuntime\*") -or $_.ExecutablePath -like "$temporaryRuntime\*")
    } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

# The service's own process holds a handle to it, and a service deleted while
# any handle is open is only *marked* for deletion: it stays enumerable,
# reporting a stale status, and cannot be opened, reconfigured or recreated
# until the last handle closes. A reinstall arriving seconds later then failed
# with "Cannot open GamePathService service on computer '.'" and aborted setup.
# So the process goes first, and the deletion is waited out rather than assumed.
Get-Process -Name 'gamepath-service' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
& sc.exe delete $serviceName | Out-Null
for ($attempt = 0; $attempt -lt 40; $attempt++) {
    if (-not (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) { break }
    Start-Sleep -Milliseconds 250
}
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    # Not fatal: the removal is complete as far as this script can make it, and
    # Windows finishes it when the last handle closes. Saying so beats leaving
    # the next install to discover it. The usual holder is an open Services or
    # Task Manager window.
    Write-Host "Windows has not finished removing $serviceName. Close any open Services or Task Manager window; a reinstall may need a moment or a restart."
}
Remove-Item -LiteralPath $programRuntime -Recurse -Force -ErrorAction SilentlyContinue
if ($legacyProgramRuntime -and $legacyProgramRuntime -ne $programRuntime) {
    Remove-Item -LiteralPath $legacyProgramRuntime -Recurse -Force -ErrorAction SilentlyContinue
}
Remove-Item -LiteralPath (Join-Path $env:ProgramData 'GamePath') -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $temporaryRuntime -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $env:APPDATA 'GamePath') -Recurse -Force -ErrorAction SilentlyContinue
