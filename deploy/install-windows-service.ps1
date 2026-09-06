[CmdletBinding()]
param(
    [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot),
    [switch]$SkipBuild,
    [switch]$LeaveStopped,
    [string]$LogPath = ''
)

$ErrorActionPreference = 'Stop'
$LogPath = if ($LogPath) { $LogPath } else { Join-Path $ProjectRoot '.runtime\service-install.log' }
$serviceName = 'GamePathService'
$isAdministrator = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdministrator) {
    $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath), '-ProjectRoot', ('"{0}"' -f $ProjectRoot), '-LogPath', ('"{0}"' -f $LogPath))
    if ($SkipBuild) { $arguments += '-SkipBuild' }
    if ($LeaveStopped) { $arguments += '-LeaveStopped' }
    $elevated = Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $arguments -Wait -PassThru
    exit $elevated.ExitCode
}

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $LogPath) | Out-Null
Start-Transcript -LiteralPath $LogPath -Force | Out-Null
trap {
    Write-Error $_
    Stop-Transcript | Out-Null
    exit 1
}

if (-not $SkipBuild) {
    & (Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe') build --release --manifest-path (Join-Path $ProjectRoot 'engine\Cargo.toml')
    if ($LASTEXITCODE -ne 0) { throw 'The GamePath native engine build failed.' }
    & (Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe') build --release --manifest-path (Join-Path $ProjectRoot 'service\Cargo.toml')
    if ($LASTEXITCODE -ne 0) { throw 'The GamePath service build failed.' }
}

$installDirectory = Join-Path $env:ProgramFiles 'GamePath'
$dataDirectory = Join-Path $env:ProgramData 'GamePath'
$serviceBinary = Join-Path $installDirectory 'gamepath-service.exe'
$tokenFile = Join-Path $dataDirectory 'service-token'
New-Item -ItemType Directory -Force -Path $installDirectory, $dataDirectory | Out-Null

$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
$gamePathInterfaceIndexes = @(Get-NetAdapter -Name 'GamePath*' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ifIndex)
if ($existing -and $existing.Status -ne 'Stopped') {
    Stop-Service -Name $serviceName -Force
    $existing.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(15))
}
# A service upgrade must never leave its separately spawned capture engine
# intercepting traffic if Service Control Manager terminates the parent early.
Get-Process -Name 'gamepath-engine' -ErrorAction SilentlyContinue | Stop-Process -Force
if ($gamePathInterfaceIndexes.Count) {
    Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceIndex -in $gamePathInterfaceIndexes -and $_.DestinationPrefix -in @('0.0.0.0/1', '128.0.0.0/1') } |
        Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
}

Copy-Item -LiteralPath (Join-Path $ProjectRoot 'service\target\release\gamepath-service.exe') -Destination $serviceBinary -Force
Copy-Item -LiteralPath (Join-Path $ProjectRoot 'engine\target\release\gamepath-engine.exe') -Destination (Join-Path $installDirectory 'gamepath-engine.exe') -Force
Copy-Item -LiteralPath (Join-Path $ProjectRoot 'vendor\wintun\wintun.dll') -Destination (Join-Path $installDirectory 'wintun.dll') -Force
Copy-Item -LiteralPath (Join-Path $ProjectRoot 'vendor\windivert\WinDivert.dll') -Destination (Join-Path $installDirectory 'WinDivert.dll') -Force
Copy-Item -LiteralPath (Join-Path $ProjectRoot 'vendor\windivert\WinDivert64.sys') -Destination (Join-Path $installDirectory 'WinDivert64.sys') -Force

if (-not (Test-Path -LiteralPath $tokenFile)) {
    $bytes = New-Object byte[] 32
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($bytes) } finally { $generator.Dispose() }
    $token = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    [IO.File]::WriteAllText($tokenFile, $token, [Text.UTF8Encoding]::new($false))
}

$currentUserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls.exe $dataDirectory /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "*$currentUserSid`:(OI)(CI)RX" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Failed to protect the GamePath service data directory.' }

if (-not $existing) {
    & sc.exe create $serviceName binPath= ('"{0}"' -f $serviceBinary) start= auto DisplayName= 'GamePath Network Service' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Failed to create the GamePath Windows service.' }
}
& sc.exe description $serviceName 'Privileged packet routing and tunnel lifecycle for GamePath.' | Out-Null
& sc.exe failure $serviceName reset= 86400 actions= restart/2000/restart/5000/none/0 | Out-Null
if ($LeaveStopped) {
    & sc.exe config $serviceName start= demand | Out-Null
    Write-Host 'GamePath Network Service is installed and left stopped for review.'
} else {
    & sc.exe config $serviceName start= auto | Out-Null
    Start-Service -Name $serviceName
    (Get-Service -Name $serviceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(15))
    Write-Host 'GamePath Network Service is installed and running.'
}
Stop-Transcript | Out-Null
