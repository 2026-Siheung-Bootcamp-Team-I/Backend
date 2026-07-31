#!/usr/bin/env bash
# EDRdog 에이전트를 macOS 에 설치한다.
#
# 하는 일:
#   1. 에이전트 바이너리를 /usr/local/bin 에 놓는다
#   2. 수집 서버에서 서버 인증서를 직접 받아 저장한다(관리자가 따로 전달할 필요가 없다)
#   3. 설정 파일을 만든다(enroll secret 포함, 0600)
#   4. LaunchDaemon 으로 등록해 부팅 시 자동 기동시킨다
#
# 못 하는 일:
#   전체 디스크 접근 권한(FDA) 승인은 자동화할 수 없다. Apple 의 TCC 는 사람이 직접 켜거나
#   MDM 프로파일로만 줄 수 있다. 스크립트가 끝나면 켜야 할 경로를 알려준다.
#
# 사용:
#   sudo ./install-macos.sh --server <호스트:포트> --enroll-secret <값> [--binary <경로>]
#
# 여러 번 실행해도 안전하다. 같은 값으로 덮어쓴다.
set -euo pipefail

SERVER=""
ENROLL_SECRET=""
BINARY=""

BIN_PATH="/usr/local/bin/edrdog-agent"
CONF_DIR="/etc/edrdog"
CONFIG_PATH="$CONF_DIR/config.json"
CERT_PATH="$CONF_DIR/server.pem"
PLIST_PATH="/Library/LaunchDaemons/com.edrdog.agent.plist"
LOG_DIR="/var/log/edrdog"
LABEL="com.edrdog.agent"

fail() { echo "오류: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server)        SERVER="${2:-}"; shift 2 ;;
    --enroll-secret) ENROLL_SECRET="${2:-}"; shift 2 ;;
    --binary)        BINARY="${2:-}"; shift 2 ;;
    *) fail "모르는 인자: $1" ;;
  esac
done

[[ "$(id -u)" == "0" ]] || fail "sudo 로 실행해야 한다"
[[ -n "$SERVER" ]] || fail "--server <호스트:포트> 가 필요하다"
[[ -n "$ENROLL_SECRET" ]] || fail "--enroll-secret <값> 이 필요하다"

# 바이너리를 안 주면 스크립트 옆에 있는 것을 쓴다(go build 산출물을 같이 배포하는 경우).
if [[ -z "$BINARY" ]]; then
  BINARY="$(cd "$(dirname "$0")" && pwd)/edrdog-agent"
fi
[[ -f "$BINARY" ]] || fail "에이전트 바이너리를 찾을 수 없다: $BINARY
  먼저 빌드해라: (cd agent && go build -o packaging/edrdog-agent ./cmd/edrdog-agent)"

echo "[1/4] 바이너리 설치"
install -m 755 "$BINARY" "$BIN_PATH"

echo "[2/4] 서버 인증서 수신 ($SERVER)"
mkdir -p "$CONF_DIR"
chmod 755 "$CONF_DIR"
# 에이전트가 이 인증서로 서버를 고정한다. 여기서는 받아오기만 한다.
# 서버 인증서가 self-signed 라 openssl 은 받아 놓고도 검증 실패로 종료코드 1 을 낸다.
# pipefail 이 켜져 있어 그 코드를 그대로 믿으면 정상 수신도 실패로 끝난다. 파일로 판단한다.
openssl s_client -connect "$SERVER" -servername "${SERVER%%:*}" </dev/null 2>/dev/null \
  | sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' > "$CERT_PATH" || true
[[ -s "$CERT_PATH" ]] || fail "서버 인증서를 받지 못했다. $SERVER 가 열려 있는지 확인해라"
chmod 644 "$CERT_PATH"

echo "[3/4] 설정 파일 작성"
# enroll secret 이 들어가므로 다른 사용자가 읽으면 안 된다.
umask 077
cat > "$CONFIG_PATH" <<EOF
{
  "base_url": "https://$SERVER",
  "enroll_secret": "$ENROLL_SECRET",
  "ca_cert_path": "$CERT_PATH"
}
EOF
chmod 600 "$CONFIG_PATH"
umask 022
mkdir -p "$LOG_DIR"

echo "[4/4] LaunchDaemon 등록"
cat > "$PLIST_PATH" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$BIN_PATH</string>
    <string>-config</string>
    <string>$CONFIG_PATH</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$LOG_DIR/agent.log</string>
  <key>StandardErrorPath</key><string>$LOG_DIR/agent.log</string>
</dict>
</plist>
EOF
chmod 644 "$PLIST_PATH"
launchctl bootout system "$PLIST_PATH" 2>/dev/null || true
launchctl bootstrap system "$PLIST_PATH" || fail "LaunchDaemon 등록 실패"

cat <<EOF

설치 완료.

남은 단계 하나(사람이 해야 한다):
  프로세스와 파일 이벤트를 받으려면 전체 디스크 접근 권한이 필요하다.
  시스템 설정 > 개인정보 보호 및 보안 > 전체 디스크 접근 에서
  아래 경로를 추가하고 켜라.

    $BIN_PATH

  켠 뒤 재시작:  sudo launchctl kickstart -k system/$LABEL

상태 확인:  sudo launchctl print system/$LABEL
로그:       tail -f $LOG_DIR/agent.log
제거:       sudo launchctl bootout system/$LABEL && sudo rm -f $PLIST_PATH $BIN_PATH && sudo rm -rf $CONF_DIR
EOF
