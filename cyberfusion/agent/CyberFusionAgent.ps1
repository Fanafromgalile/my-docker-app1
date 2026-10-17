<#
.SYNOPSIS
  CyberFusion Windows endpoint agent (MVP).

.DESCRIPTION
  Outbound-only: the agent POSTs approved telemetry to the CyberFusion API over HTTPS.
  It opens no listening port and has NO remote-command interface - the server cannot make it run anything.

  Collected (and nothing else):
    - computer name, OS, IP, agent version, uptime
    - Defender real-time protection status, firewall profile status, last patch date
    - (optional) failed / interactive logon events from the Security log: user name + source IP only

.EXAMPLE
  # 1) Enroll once (elevated PowerShell). Get the token from Assets > Enroll endpoint in the dashboard.
  .\CyberFusionAgent.ps1 -Enroll -Server "https://cyberfusion.example.com" -EnrollmentToken "enr_..."

  # 2) Install as a scheduled task that runs at boot as SYSTEM
  .\CyberFusionAgent.ps1 -Install

  # 3) Or run in the foreground
  .\CyberFusionAgent.ps1 -Run
#>
[CmdletBinding()]
param(
  [switch]$Enroll,
  [switch]$Install,
  [switch]$Uninstall,
  [switch]$Run,
  [string]$Server,
  [string]$EnrollmentToken,
  [int]$IntervalSeconds = 60,
  [switch]$NoEventCollection,
  [switch]$AllowInsecure   # development only: permits http:// to localhost
)

$ErrorActionPreference = "Stop"
$AgentVersion = "0.1.0"
$DataDir = Join-Path $env:ProgramData "CyberFusion"
$ConfigPath = Join-Path $DataDir "agent.json"
$TaskName = "CyberFusionAgent"
Add-Type -AssemblyName System.Security

# ---------- helpers ----------
function Assert-Server([string]$Url) {
  if ($Url -match '^https://') { return }
  if ($AllowInsecure -and $Url -match '^http://(localhost|127\.0\.0\.1)') {
    Write-Warning "Using plain HTTP to localhost (development only)."; return
  }
  throw "Refusing to send data over an unencrypted or invalid server URL '$Url'. Use https://."
}

# Token is encrypted with DPAPI (machine scope) so it is not stored as plaintext on disk.
function Protect-Secret([string]$Plain) {
  $bytes = [Text.Encoding]::UTF8.GetBytes($Plain)
  $enc = [Security.Cryptography.ProtectedData]::Protect($bytes, $null, 'LocalMachine')
  [Convert]::ToBase64String($enc)
}
function Unprotect-Secret([string]$Blob) {
  $dec = [Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($Blob), $null, 'LocalMachine')
  [Text.Encoding]::UTF8.GetString($dec)
}

function Save-Config($cfg) {
  if (-not (Test-Path $DataDir)) { New-Item -ItemType Directory -Path $DataDir | Out-Null }
  $cfg | ConvertTo-Json | Set-Content -Path $ConfigPath -Encoding UTF8
  # Restrict the folder to SYSTEM and Administrators.
  & icacls $DataDir /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null
}
function Load-Config {
  if (-not (Test-Path $ConfigPath)) { throw "Agent is not enrolled. Run with -Enroll first." }
  Get-Content $ConfigPath -Raw | ConvertFrom-Json
}

function Get-PrimaryIp {
  try {
    (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' } |
      Select-Object -First 1).IPv4Address.IPAddress
  } catch { "" }
}

function Get-Telemetry {
  $t = [ordered]@{}
  try { $os = Get-CimInstance Win32_OperatingSystem
        $t.uptime_hours = [int]((Get-Date) - $os.LastBootUpTime).TotalHours } catch {}
  try { $mp = Get-MpComputerStatus
        $t.defender_enabled = [bool]$mp.RealTimeProtectionEnabled
        $t.defender_signature_age_days = [int]$mp.AntivirusSignatureAge } catch { $t.defender_enabled = $null }
  try { $profiles = Get-NetFirewallProfile
        $t.firewall_enabled = -not ($profiles | Where-Object { $_.Enabled -eq 'False' -or $_.Enabled -eq $false })
        $t.firewall_profiles = @($profiles | ForEach-Object { "$($_.Name)=$($_.Enabled)" }) } catch { $t.firewall_enabled = $null }
  try { $hf = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
        if ($hf.InstalledOn) { $days = [int]((Get-Date) - $hf.InstalledOn).TotalDays
          $t.last_patch_days_ago = $days
          $t.patch_status = if ($days -gt 45) { "pending" } else { "current" } } } catch {}
  $t
}

function Invoke-Api([string]$Method, [string]$Url, $Body, [string]$Token) {
  $headers = @{}
  if ($Token) { $headers["Authorization"] = "Bearer $Token" }
  $json = $Body | ConvertTo-Json -Depth 6 -Compress
  Invoke-RestMethod -Method $Method -Uri $Url -Headers $headers -ContentType "application/json" -Body $json -TimeoutSec 30
}

# ---------- enrollment ----------
function Invoke-Enroll {
  if (-not $Server -or -not $EnrollmentToken) { throw "-Server and -EnrollmentToken are required with -Enroll." }
  $Server = $Server.TrimEnd('/')
  Assert-Server $Server
  $os = (Get-CimInstance Win32_OperatingSystem)
  $res = Invoke-Api POST "$Server/api/agents/enroll" @{
    enrollment_token = $EnrollmentToken; hostname = $env:COMPUTERNAME
    os = "$($os.Caption) $($os.Version)"; ip = (Get-PrimaryIp); agent_version = $AgentVersion } $null
  Save-Config @{ server = $Server; agent_id = $res.agent_id; token = (Protect-Secret $res.agent_token)
                 last_event_time = (Get-Date).ToUniversalTime().ToString("o") }
  Write-Host "Enrolled as agent #$($res.agent_id). Config saved to $ConfigPath"
}

# ---------- event collection ----------
function Get-SecurityEvents([datetime]$Since) {
  $out = @()
  try {
    $events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624, 4625; StartTime = $Since } -MaxEvents 300 -ErrorAction Stop
  } catch { return $out }   # no events, or the agent is not running elevated
  foreach ($e in $events) {
    $x = [xml]$e.ToXml()
    $d = @{}; foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
    $user = $d["TargetUserName"]
    if (-not $user -or $user.EndsWith('$') -or $user -in @("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON")) { continue }
    $ip = $d["IpAddress"]; if ($ip -in @("-", "::1", "127.0.0.1")) { $ip = "" }
    if ($e.Id -eq 4625) {
      $out += @{ event_type = "auth_failure"; user = $user; src_ip = "$ip"; outcome = "failure"; message = "An account failed to log on (4625)" }
    } elseif ($d["LogonType"] -in @("2", "7", "10")) {   # interactive, unlock, RDP only - skips noisy service logons
      $out += @{ event_type = "auth_success"; user = $user; src_ip = "$ip"; outcome = "success"; message = "An account was successfully logged on (4624)" }
    }
  }
  $out
}

# ---------- main loop ----------
function Invoke-Run {
  $cfg = Load-Config
  Assert-Server $cfg.server
  $os = (Get-CimInstance Win32_OperatingSystem)
  Write-Host "CyberFusion agent $AgentVersion running; reporting to $($cfg.server) every $IntervalSeconds s. Ctrl+C to stop."
  $backoff = 0
  while ($true) {
    try {
      $token = Unprotect-Secret $cfg.token
      Invoke-Api POST "$($cfg.server)/api/agents/heartbeat" @{
        hostname = $env:COMPUTERNAME; os = "$($os.Caption) $($os.Version)"; ip = (Get-PrimaryIp)
        agent_version = $AgentVersion; telemetry = (Get-Telemetry) } $token | Out-Null

      if (-not $NoEventCollection) {
        $since = [datetime]::Parse($cfg.last_event_time).ToUniversalTime()
        $now = (Get-Date).ToUniversalTime()
        $evs = @(Get-SecurityEvents $since.ToLocalTime())
        if ($evs.Count -gt 0) { Invoke-Api POST "$($cfg.server)/api/agents/events" $evs $token | Out-Null }
        $cfg.last_event_time = $now.ToString("o"); Save-Config $cfg
      }
      $backoff = 0
    } catch {
      $status = $_.Exception.Response.StatusCode.value__
      if ($status -eq 401) { Write-Error "Server rejected this agent's token (revoked or invalid). Stopping."; return }
      $backoff = [Math]::Min(300, [Math]::Max(10, $backoff * 2))   # exponential backoff, max 5 min
      Write-Warning "Report failed ($($_.Exception.Message)). Retrying in $backoff s."
    }
    Start-Sleep -Seconds ([Math]::Max($IntervalSeconds, $backoff))
  }
}

# ---------- install / uninstall ----------
function Invoke-Install {
  Load-Config | Out-Null
  $dest = Join-Path $DataDir "CyberFusionAgent.ps1"
  Copy-Item $PSCommandPath $dest -Force
  $args = "-NoProfile -ExecutionPolicy RemoteSigned -File `"$dest`" -Run -IntervalSeconds $IntervalSeconds"
  $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $args
  $trigger = New-ScheduledTaskTrigger -AtStartup
  $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
  $settings = New-ScheduledTaskSettingsSet -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
  Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
  Start-ScheduledTask -TaskName $TaskName
  Write-Host "Installed and started scheduled task '$TaskName' (runs as SYSTEM at boot)."
}
function Invoke-Uninstall {
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
  Write-Host "Task removed. Delete $DataDir to remove the stored credential."
}

if ($Enroll) { Invoke-Enroll }
elseif ($Install) { Invoke-Install }
elseif ($Uninstall) { Invoke-Uninstall }
elseif ($Run) { Invoke-Run }
else { Get-Help $PSCommandPath -Examples }
