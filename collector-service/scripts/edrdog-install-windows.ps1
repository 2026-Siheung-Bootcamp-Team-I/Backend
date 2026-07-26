<#
.SYNOPSIS
  EDRdog 엔드포인트 설치 (Windows). 온보딩 화면이 이 스크립트를 2줄로 실행시킨다.

.DESCRIPTION
  하는 일:
    1. osquery 설치(없을 때만, winget)
    2. 서버 인증서를 수집 포트에서 직접 받아 저장  ← 관리자에게 따로 받을 필요가 없다
    3. enroll secret / 플래그 파일 배치
    4. osqueryd 를 Windows 서비스로 등록하고 시작

  macOS 와 달리 FDA 같은 사람 승인 단계가 없다. 관리자 권한 PowerShell 이면 끝까지 자동이다.

  ⚠ 이 스크립트는 아직 실제 Windows 기기에서 검증되지 않았다. 실패하면 온보딩 화면의
  "수동으로 설치하기" 절차를 쓰면 된다.

.PARAMETER TlsHost
  수집 서버 주소 host:port (예: edrdog.example.com:30443)

.PARAMETER EnrollSecret
  온보딩 1번에서 발급한 값

.EXAMPLE
  irm <이 파일 raw URL> -OutFile edrdog-install.ps1
  .\edrdog-install.ps1 -TlsHost edrdog.example.com:30443 -EnrollSecret abc123
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$TlsHost,
    [Parameter(Mandatory = $true)][string]$EnrollSecret
)

$ErrorActionPreference = 'Stop'

$ConfDir     = 'C:\ProgramData\osquery'
$FlagsPath   = Join-Path $ConfDir 'osquery.flags'
$CertPath    = Join-Path $ConfDir 'osquery-server.pem'
$SecretPath  = Join-Path $ConfDir 'enroll.secret'
$OsqueryExe  = 'C:\Program Files\osquery\osqueryd\osqueryd.exe'

function Log  { param($m) Write-Host "[edrdog] $m" -ForegroundColor Cyan }
function Fail { param($m) Write-Host "[edrdog] $m" -ForegroundColor Red; exit 1 }

# 관리자 권한 확인. 서비스 등록과 ProgramData 쓰기에 필요하다.
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Fail '관리자 권한 PowerShell 에서 실행해야 한다' }

# --- 1. osquery ---
if (Test-Path $OsqueryExe) {
    Log 'osquery 이미 설치됨'
} else {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Fail 'winget 이 없다. https://osquery.io/downloads 에서 직접 설치할 것'
    }
    Log 'osquery 설치 중 (몇 분 걸릴 수 있다)'
    winget install --id osquery.osquery -e --accept-source-agreements --accept-package-agreements | Out-Null
    if (-not (Test-Path $OsqueryExe)) { Fail "설치 후에도 $OsqueryExe 가 없다" }
}

New-Item -ItemType Directory -Force -Path $ConfDir | Out-Null

# --- 2. 서버 인증서 ---
# osquery 는 이 인증서를 핀해서 검증한다. 수집 포트에서 직접 받아오므로 따로 전달받을 필요가 없다.
Log "서버 인증서 받는 중 ($TlsHost)"
$hostName, $port = $TlsHost.Split(':')
if (-not $port) { $port = 443 }
try {
    $tcp = [System.Net.Sockets.TcpClient]::new($hostName, [int]$port)
    # 인증서를 '받아오는' 단계라 검증하지 않는다. 이후 osquery 가 이 파일로 핀 검증을 한다.
    # 콜백은 델리게이트 타입으로 명시 캐스팅한다(스크립트블록 암묵 변환은 PowerShell 버전에 따라 실패한다).
    $noValidation = [System.Net.Security.RemoteCertificateValidationCallback] { param($s, $c, $ch, $e) $true }
    $ssl = [System.Net.Security.SslStream]::new($tcp.GetStream(), $false, $noValidation)
    $ssl.AuthenticateAsClient($hostName)
    $raw = $ssl.RemoteCertificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $b64 = [Convert]::ToBase64String($raw, [Base64FormattingOptions]::InsertLineBreaks)
    "-----BEGIN CERTIFICATE-----`n$b64`n-----END CERTIFICATE-----" |
        Set-Content -Path $CertPath -Encoding ascii
} catch {
    Fail "수집 서버에 붙지 못했다: $TlsHost (주소·방화벽 확인) — $_"
} finally {
    if ($ssl) { $ssl.Dispose() }
    if ($tcp) { $tcp.Dispose() }
}

# --- 3. enroll secret + 플래그 ---
# 개행이 붙으면 secret 이 달라진다. NoNewline 필수.
[System.IO.File]::WriteAllText($SecretPath, $EnrollSecret)

# gflags 는 줄 끝 주석을 잘라내지 않는다. 주석은 줄 전체로만 쓴다.
@"
# EDRdog osquery 플래그 (설치 스크립트가 생성). 수집 쿼리는 서버가 config 로 내려준다.
--enroll_secret_path=$SecretPath
--tls_hostname=$TlsHost
--tls_server_certs=$CertPath

--config_plugin=tls
--config_tls_endpoint=/api/osquery/config
--config_refresh=60
--enroll_tls_endpoint=/api/osquery/enroll

--logger_plugin=tls
--logger_tls_endpoint=/api/osquery/log
--logger_tls_period=10
--disable_carver=true

# 퍼블리셔마다 켜는 플래그가 다르다. 빠지면 osquery 가 에러 없이 빈 결과를 준다.
--disable_events=false
# 프로세스 생성 (ETW). 이 플래그가 없으면 Windows 수집은 전부 0건이다.
--enable_process_etw_events=true
# 파일 변경 (NTFS USN 저널)
--enable_ntfs_event_publisher=true

--host_identifier=hostname
--disable_watchdog=true
"@ | Set-Content -Path $FlagsPath -Encoding ascii

Log "설정 배치 완료 ($FlagsPath)"

# --- 4. 서비스 등록 ---
# 이미 있으면 지우고 다시 만든다(플래그 경로가 바뀌었을 수 있다).
if (Get-Service osqueryd -ErrorAction SilentlyContinue) {
    Stop-Service osqueryd -Force -ErrorAction SilentlyContinue
    sc.exe delete osqueryd | Out-Null
    Start-Sleep -Seconds 2
}
sc.exe create osqueryd binPath= "`"$OsqueryExe`" --flagfile=`"$FlagsPath`"" start= auto DisplayName= "osquery daemon (EDRdog)" | Out-Null
Start-Service osqueryd
Start-Sleep -Seconds 3

$svc = Get-Service osqueryd
if ($svc.Status -ne 'Running') { Fail "서비스가 시작되지 않았다 (상태: $($svc.Status))" }

Write-Host ''
Log "설치 완료. osqueryd 서비스 실행 중 (host=$env:COMPUTERNAME)"
Write-Host @"

수집이 시작되면 온보딩 4번 기기 상태에 이 기기가 나타납니다.
프로세스 감시가 ETW 라 별도 권한 승인은 필요 없습니다.

상태 확인:  Get-Service osqueryd
제거:       Stop-Service osqueryd; sc.exe delete osqueryd; Remove-Item -Recurse $ConfDir
"@
