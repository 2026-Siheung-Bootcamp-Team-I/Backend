# EDRdog 에이전트 설치. 이 파일은 서버가 설치 링크로 내려준다.
#
#   irm https://<서버>/i/<토큰>.ps1 | iex
#
# 서버 주소와 enroll secret 은 내려줄 때 이미 채워져 있다. 받는 사람이 키를 다룰 일이 없다.
# 관리자 권한 PowerShell 에서 실행해야 한다.
#
# 소스에서 직접 깔고 싶으면 agent/packaging/install-windows.ps1 을 쓴다.
#
# macOS 와 달리 사람이 승인할 단계가 없다. ETW 는 LocalSystem 이면 권한이 이미 있다.

$ErrorActionPreference = 'Stop'

$Server        = '{{SERVER}}'
$EnrollSecret  = '{{ENROLL_SECRET}}'
$DownloadBase  = '{{DOWNLOAD_BASE}}'

$InstallDir  = 'C:\Program Files\EDRdog'
$ConfDir     = 'C:\ProgramData\EDRdog'
$BinPath     = Join-Path $InstallDir 'edrdog-agent.exe'
$ConfigPath  = Join-Path $ConfDir 'config.json'
$CertPath    = Join-Path $ConfDir 'server.pem'
$LogPath     = Join-Path $ConfDir 'agent.log'
$ServiceName = 'edrdog-agent'

# 등록에 성공하면 에이전트가 남기는 줄. 서비스가 떠 있다는 것과 서버에 붙었다는 것은 다른 말이다.
$EnrolledMark = '등록 완료'

function Fail($message) {
    Write-Error "오류: $message"
    exit 1
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail '관리자 권한 PowerShell 에서 실행해야 한다'
}

# --- 1. 바이너리 ---
Write-Host '[1/4] 에이전트를 받는다'
$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { 'amd64' }
    'ARM64' { 'arm64' }
    default { Fail "지원하지 않는 아키텍처: $($env:PROCESSOR_ARCHITECTURE)" }
}
$asset = "edrdog-agent-windows-$arch.exe"
$tmp = Join-Path $env:TEMP ([System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$downloaded = Join-Path $tmp 'agent.exe'
try {
    Invoke-WebRequest -Uri "$DownloadBase/$asset" -OutFile $downloaded -UseBasicParsing
} catch {
    Fail "바이너리를 받지 못했다: $DownloadBase/$asset ($($_.Exception.Message))"
}

# 받은 것이 온전한지 본다. 끊긴 다운로드는 크기만 작고 그대로 설치돼서, 깔린 뒤에
# "왜 안 뜨지" 로 시간을 버리게 된다.
#
# try 로 감싸는 것은 해시 파일을 받는 것까지다. 비교까지 같이 감싸면 불일치가 catch 로
# 흘러들어 경고로 강등되고 설치가 그대로 이어진다. 그러면 검사가 있으나 마나다.
$want = $null
try {
    $want = (Invoke-WebRequest -Uri "$DownloadBase/$asset.sha256" -UseBasicParsing).Content
} catch {
    # 릴리스에 해시 파일이 없을 수 있다. 그 사실을 조용히 넘기지는 않는다.
    Write-Warning "$asset.sha256 이 없어 무결성을 확인하지 못했다"
}
if ($want) {
    # 파일 모양은 "<해시>  <파일명>" 이다. 해시는 첫 칸에 있다. 16진수만 남기고 뒤에서
    # 자르면 파일명 끝을 해시로 읽는다(실제로 그렇게 짰다가 모든 설치가 막혔다).
    # edrdog-agent-windows-amd64.exe 는 a, d, e, 6, 4 처럼 16진수로 보이는 글자가 많다.
    $want = (($want -split '\s+') | Where-Object { $_ })[0]
    # 64자 16진수가 아니면 비교 자체가 무의미하다. 그걸 "일치하지 않음" 으로 뭉뚱그리면
    # 릴리스 파일이 깨진 것과 바이너리가 바뀐 것을 구별할 수 없다.
    if ($want -notmatch '^[A-Fa-f0-9]{64}$') { Fail "$asset.sha256 의 모양이 예상과 다르다: $want" }
    $got = (Get-FileHash -Path $downloaded -Algorithm SHA256).Hash
    if ($want -ne $got) { Fail "받은 바이너리의 해시가 다르다 (기대 $want, 실제 $got)" }
    Write-Host '  해시 확인됨.'
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
# 기존 서비스가 exe 를 물고 있으면 복사가 실패한다. 먼저 멈춘다.
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing -and $existing.Status -ne 'Stopped') { Stop-Service -Name $ServiceName -Force }
Copy-Item -Force $downloaded $BinPath
Remove-Item -Recurse -Force $tmp

# --- 2. 인증서 ---
Write-Host "[2/4] 서버 인증서 수신 ($Server)"
New-Item -ItemType Directory -Force -Path $ConfDir | Out-Null
$parts = $Server.Split(':')
$hostName = $parts[0]
$port = if ($parts.Length -gt 1) { [int]$parts[1] } else { 443 }

$tcp = $null
$ssl = $null
try {
    $tcp = [System.Net.Sockets.TcpClient]::new($hostName, $port)
    # 여기서는 받아오기만 한다. 실제 검증은 에이전트가 이 파일로 고정해서 한다.
    $callback = [System.Net.Security.RemoteCertificateValidationCallback] { param($s, $c, $ch, $e) $true }
    $ssl = [System.Net.Security.SslStream]::new($tcp.GetStream(), $false, $callback)
    $ssl.AuthenticateAsClient($hostName)
    $der = $ssl.RemoteCertificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $b64 = [Convert]::ToBase64String($der, [Base64FormattingOptions]::InsertLineBreaks)
    "-----BEGIN CERTIFICATE-----`n$b64`n-----END CERTIFICATE-----" |
        Set-Content -Path $CertPath -Encoding ascii
} catch {
    Fail "서버 인증서를 받지 못했다: $($_.Exception.Message)"
} finally {
    if ($ssl) { $ssl.Dispose() }
    if ($tcp) { $tcp.Dispose() }
}

# --- 3. 설정과 서비스 ---
Write-Host '[3/4] 설정 파일 작성과 서비스 등록'
$config = @"
{
  "base_url": "https://$Server",
  "enroll_secret": "$EnrollSecret",
  "ca_cert_path": "$($CertPath -replace '\\', '\\\\')"
}
"@
[System.IO.File]::WriteAllText($ConfigPath, $config)

# enroll secret 과 로그는 일반 사용자가 읽으면 안 된다. 상속을 끊고 SYSTEM 과 Administrators 만 남긴다.
foreach ($path in @($ConfigPath)) {
    $acl = Get-Acl $path
    $acl.SetAccessRuleProtection($true, $false)
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
    foreach ($who in @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')) {
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($who, 'FullControl', 'Allow')))
    }
    Set-Acl -Path $path -AclObject $acl
}

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    # sc.exe delete 는 비동기라 곧바로 New-Service 를 부르면 아직 지워지지 않아 실패한다.
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

# New-Service 를 쓰는 이유: sc.exe 는 PowerShell 5.1 에서 공백이 든 경로를 binPath 로 넘길 때
# 따옴표가 그대로 전달되지 않아 등록이 실패하고, 그 실패가 화면에 안 남아
# 다음 줄 Start-Service 에서 "서비스를 찾을 수 없다"는 엉뚱한 오류로만 드러난다.
# -log 를 붙이는 이유: Windows 서비스는 stderr 가 아무 데도 가지 않는다. 안 붙이면
# 에이전트가 남긴 이유별 카운터를 읽을 방법이 없다.
$binaryPathName = '"{0}" -config "{1}" -log "{2}" -service' -f $BinPath, $ConfigPath, $LogPath
New-Service -Name $ServiceName `
    -BinaryPathName $binaryPathName `
    -DisplayName 'EDRdog Agent' `
    -Description '엔드포인트 행위를 수집해 EDRdog 서버로 보낸다' `
    -StartupType Automatic | Out-Null

# --- 4. 확인 ---
Write-Host '[4/4] 기동하고 확인한다'
# 지금까지의 로그는 이전 실행 것이다. 여기부터 새로 나온 줄만 본다.
$before = 0
if (Test-Path $LogPath) { $before = (Get-Content $LogPath).Count }
Start-Service -Name $ServiceName

$enrolled = $false
foreach ($i in 1..30) {
    Start-Sleep -Seconds 1
    $service = Get-Service -Name $ServiceName
    if ($service.Status -ne 'Running' -and $service.Status -ne 'StartPending') {
        Fail "서비스가 멈췄다 (상태: $($service.Status)). 로그: $LogPath"
    }
    if (-not (Test-Path $LogPath)) { continue }
    $lines = @(Get-Content $LogPath -ErrorAction SilentlyContinue)
    # 로그가 잘렸으면 처음부터 다시 본다.
    if ($lines.Count -lt $before) { $before = 0 }
    $fresh = $lines | Select-Object -Skip $before
    if ($fresh -match [regex]::Escape($EnrolledMark)) { $enrolled = $true; break }
}

Write-Host ''
if (-not $enrolled) {
    # 서비스가 떠 있는 것만 보고 끝냈다고 하면 아무것도 안 오는 채로 설치가 끝난다.
    Write-Host '30초 안에 등록 로그가 안 보인다. 아래를 직접 확인해라.'
    Write-Host "  로그:   Get-Content -Tail 50 '$LogPath'"
    Write-Host "  상태:   Get-Service $ServiceName"
    exit 1
}

Write-Host '끝났다. 대시보드에 이 기기가 뜬다.'
Write-Host "로그:  Get-Content -Wait -Tail 20 '$LogPath'"
Write-Host "제거:  Stop-Service $ServiceName; sc.exe delete $ServiceName; Remove-Item -Recurse '$InstallDir','$ConfDir'"
