#!/usr/bin/env bash
#
# EDRdog 엔드포인트 설치 (macOS). 온보딩 화면이 이 스크립트를 한 줄로 실행시킨다.
#
#   curl -fsSL <이 파일 raw URL> | sudo bash -s -- \
#     --tls-host <수집서버:포트> --enroll-secret <값> [--with-zeek]
#
# 하는 일:
#   1. osquery 설치(없을 때만)
#   2. 서버 인증서를 수집 포트에서 직접 받아 저장  ← 관리자에게 따로 받을 필요가 없다
#   3. enroll secret / 플래그 파일 배치
#   4. launchd 데몬으로 osquery 기동
#   5. --with-zeek 면 Zeek + 전송기까지 데몬으로 등록 (네트워크 이벤트, 위협 지도용)
#
# 못 하는 일:
#   전체 디스크 접근(FDA) 승인. macOS TCC 라 사람이 시스템 설정에서 직접 켜야 한다.
#   스크립트가 끝나면서 경로를 출력하니 그것만 하면 된다.
#
# 여러 번 실행해도 안전하다(같은 값으로 덮어쓴다).
set -euo pipefail

TLS_HOST=""
ENROLL_SECRET=""
WITH_ZEEK=0
SHIPPER_URL="https://raw.githubusercontent.com/2026-Siheung-Bootcamp-Team-I/Backend/main/collector-service/zeek/edrdog-zeek-shipper.py"

OSQUERY_BIN="/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd"
FLAGS_PATH="/var/osquery/osquery.flags"        # launchd 잡이 읽는 고정 경로
CONF_DIR="/etc/osquery"
ZEEK_LOG_DIR="/var/log/edrdog-zeek"
SHIPPER_PATH="/usr/local/bin/edrdog-zeek-shipper.py"

log()  { printf '\033[1m[edrdog]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[edrdog] %s\033[0m\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --tls-host)      TLS_HOST="${2:-}"; shift 2 ;;
    --enroll-secret) ENROLL_SECRET="${2:-}"; shift 2 ;;
    --with-zeek)     WITH_ZEEK=1; shift ;;
    *) fail "알 수 없는 옵션: $1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || fail "sudo 로 실행해야 한다 (파일 배치와 데몬 등록에 필요)"
[ -n "$TLS_HOST" ]      || fail "--tls-host 가 필요하다 (예: edrdog.example.com:30443)"
[ -n "$ENROLL_SECRET" ] || fail "--enroll-secret 이 필요하다 (온보딩 1번에서 발급)"

# brew 는 root 로 못 돌린다. sudo 로 실행됐으니 원래 사용자로 되돌려 호출한다.
REAL_USER="${SUDO_USER:-$(stat -f '%Su' /dev/console)}"
run_as_user() { sudo -u "$REAL_USER" -H "$@"; }

# --- 1. osquery ---
if [ -x "$OSQUERY_BIN" ]; then
  log "osquery 이미 설치됨"
else
  command -v brew >/dev/null || fail "Homebrew 가 필요하다. https://brew.sh 참고"
  log "osquery 설치 중 (몇 분 걸릴 수 있다)"
  run_as_user brew install --cask osquery
  [ -x "$OSQUERY_BIN" ] || fail "osquery 설치 후에도 $OSQUERY_BIN 이 없다"
fi

# --- 2. 서버 인증서 ---
# osquery 는 이 인증서를 핀해서 검증한다. 수집 포트에서 직접 받아오므로 따로 전달받을 필요가 없다.
log "서버 인증서 받는 중 ($TLS_HOST)"
mkdir -p "$CONF_DIR"
if ! echo | openssl s_client -connect "$TLS_HOST" -servername "${TLS_HOST%%:*}" 2>/dev/null \
     | sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' > "$CONF_DIR/osquery-server.pem"; then
  fail "수집 서버에 붙지 못했다: $TLS_HOST (주소·방화벽 확인)"
fi
[ -s "$CONF_DIR/osquery-server.pem" ] || fail "인증서를 받지 못했다: $TLS_HOST"
chmod 644 "$CONF_DIR/osquery-server.pem"

# --- 3. enroll secret + 플래그 ---
printf '%s' "$ENROLL_SECRET" > "$CONF_DIR/enroll.secret"
chmod 600 "$CONF_DIR/enroll.secret"

mkdir -p "$(dirname "$FLAGS_PATH")"
# gflags 는 줄 끝 주석을 잘라내지 않는다. 주석은 줄 전체로만 쓴다.
cat > "$FLAGS_PATH" <<FLAGS
# EDRdog osquery 플래그 (설치 스크립트가 생성). 수집 쿼리는 서버가 config 로 내려준다.
--enroll_secret_path=$CONF_DIR/enroll.secret
--tls_hostname=$TLS_HOST
--tls_server_certs=$CONF_DIR/osquery-server.pem

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
# 프로세스 생성 (EndpointSecurity). FDA 가 있어야 실제로 채워진다.
--disable_endpointsecurity=false
# 파일 변경 (FSEvents)
--enable_file_events=true
# 아웃바운드 연결 (OpenBSM). 신형 macOS 에서는 비어 있을 수 있어 네트워크는 Zeek 가 담당한다.
--disable_audit=false
--audit_allow_config=true
--audit_allow_sockets=true

--host_identifier=hostname
--disable_watchdog=true
FLAGS
chmod 644 "$FLAGS_PATH"
log "설정 배치 완료 ($FLAGS_PATH)"

# --- 4. 기동 ---
osqueryctl stop >/dev/null 2>&1 || true
osqueryctl start >/dev/null 2>&1 || fail "osquery 기동 실패. 'sudo osqueryctl status' 로 확인"
log "osquery 기동됨 (host=$(hostname))"

# --- 5. Zeek (선택) ---
if [ "$WITH_ZEEK" -eq 1 ]; then
  ZEEK_BIN="$(command -v zeek || echo /opt/homebrew/bin/zeek)"
  if [ ! -x "$ZEEK_BIN" ]; then
    log "Zeek 설치 중"
    run_as_user brew install zeek
    ZEEK_BIN="$(command -v zeek || echo /opt/homebrew/bin/zeek)"
  fi
  [ -x "$ZEEK_BIN" ] || fail "zeek 를 찾지 못했다"

  IFACE="$(route get default 2>/dev/null | awk '/interface:/{print $2}')"
  [ -n "$IFACE" ] || fail "기본 네트워크 인터페이스를 찾지 못했다"

  curl -fsSL "$SHIPPER_URL" -o "$SHIPPER_PATH" || fail "전송기 내려받기 실패"
  chmod 755 "$SHIPPER_PATH"
  mkdir -p "$ZEEK_LOG_DIR"

  # -C 는 필수. 맥 네트워크 카드가 체크섬을 나중에 채워서, 없으면 Zeek 가 패킷을 전부 버린다.
  cat > /Library/LaunchDaemons/com.edrdog.zeek.plist <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.edrdog.zeek</string>
  <key>ProgramArguments</key><array>
    <string>$ZEEK_BIN</string><string>-C</string><string>-i</string><string>$IFACE</string>
    <string>LogAscii::use_json=T</string><string>local</string>
  </array>
  <key>WorkingDirectory</key><string>$ZEEK_LOG_DIR</string>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
</dict></plist>
PLIST

  cat > /Library/LaunchDaemons/com.edrdog.zeek-shipper.plist <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.edrdog.zeek-shipper</string>
  <key>ProgramArguments</key><array>
    <string>/usr/bin/python3</string><string>$SHIPPER_PATH</string>
    <string>--conn-log</string><string>$ZEEK_LOG_DIR/conn.log</string>
    <string>--tls-host</string><string>$TLS_HOST</string>
  </array>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
</dict></plist>
PLIST

  for job in com.edrdog.zeek com.edrdog.zeek-shipper; do
    launchctl unload "/Library/LaunchDaemons/$job.plist" >/dev/null 2>&1 || true
    launchctl load -w "/Library/LaunchDaemons/$job.plist" || fail "$job 등록 실패"
  done
  log "Zeek + 전송기 데몬 등록됨 (인터페이스 $IFACE, 로그 $ZEEK_LOG_DIR)"
fi

cat <<DONE

설치가 끝났습니다. 마지막 한 단계는 직접 해야 합니다.

  전체 디스크 접근(FDA) 승인
  시스템 설정 → 개인정보 보호 및 보안 → 전체 디스크 접근 → "+" → Cmd+Shift+G 로 아래 경로 추가

    $OSQUERY_BIN

  이 권한은 macOS 가 사람 승인만 받도록 막아둔 것이라 자동화할 수 없습니다.
  승인한 뒤 재부팅하면 프로세스 이벤트가 수집되기 시작합니다.

상태 확인:  sudo osqueryctl status
제거:       sudo osqueryctl stop && sudo rm -rf $CONF_DIR $FLAGS_PATH
DONE
