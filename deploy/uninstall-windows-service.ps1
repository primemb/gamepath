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
$programRuntime = Join-Path $env:ProgramFiles 'GamePath'
$temporaryRuntime = Join-Path $env:TEMP 'GamePath'
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Name -like 'gamepath-engine*.exe' -and
        ($_.ExecutablePath -like "$programRuntime\*" -or $_.ExecutablePath -like "$temporaryRuntime\*")
    } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

& sc.exe delete $serviceName | Out-Null
Remove-Item -LiteralPath $programRuntime -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $env:ProgramData 'GamePath') -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $temporaryRuntime -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $env:APPDATA 'GamePath') -Recurse -Force -ErrorAction SilentlyContinue
