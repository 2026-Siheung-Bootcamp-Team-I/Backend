#!/usr/bin/env bash
# EDRdog 에이전트 설치. 이 파일은 서버가 설치 링크로 내려준다.
#
#   curl -fsSL https://<서버>/i/<토큰> | sudo bash
#
# 서버 주소와 enroll secret 은 내려줄 때 이미 채워져 있다. 받는 사람이 키를 다룰 일이 없다.
# 설치가 귀찮으면 안 깔고, 안 깔면 수집기가 아무리 좋아도 소용이 없다.
#
# 소스에서 직접 깔고 싶으면 agent/packaging/bootstrap-macos.sh 를 쓴다. 그 쪽은 로컬에서
# 빌드하는 개발용 경로고, 이 파일은 배포된 바이너리를 받아 까는 배포용 경로다.
set -euo pipefail

SERVER="{{SERVER}}"
ENROLL_SECRET="{{ENROLL_SECRET}}"
DOWNLOAD_BASE="{{DOWNLOAD_BASE}}"

BIN_PATH="/usr/local/bin/edrdog-agent"
CONF_DIR="/etc/edrdog"
CONFIG_PATH="$CONF_DIR/config.json"
CERT_PATH="$CONF_DIR/server.pem"
PLIST_PATH="/Library/LaunchDaemons/com.edrdog.agent.plist"
LOG_DIR="/var/log/edrdog"
LOG_PATH="$LOG_DIR/agent.log"
LABEL="com.edrdog.agent"

# 등록에 성공하면 에이전트가 남기는 줄. 이 줄이 떠야 서버까지 붙은 것이다.
ENROLLED_MARK="등록 완료"
# 권한이 없으면 eslogger 가 내는 오류. 붙었는지 아닌지보다 이 쪽이 더 흔한 실패다.
DENIED_MARK="ERR_NOT_PERMITTED"

fail() { echo "오류: $*" >&2; exit 1; }
step() { echo; echo "== $*"; }

[[ "$(id -u)" == "0" ]] || fail "sudo 로 실행해야 한다:  curl -fsSL <링크> | sudo bash"
# 권한을 켤 때까지 기다려야 한다. 사람이 앞에 없으면 못 한다.
# curl 로 받아 실행하면 stdin 은 스크립트 자신이라 /dev/tty 로 따로 읽는다.
[[ -r /dev/tty ]] || fail "터미널에서 직접 실행해야 한다 (권한 승인을 기다려야 한다)"

# sudo 이전 사용자로 되돌려 GUI 를 연다. root 로 열면 로그인 세션이 아닌 곳에 창이 뜬다.
RUN_AS="${SUDO_USER:-}"
as_user() {
  if [[ -n "$RUN_AS" && "$RUN_AS" != "root" ]]; then
    sudo -u "$RUN_AS" "$@"
  else
    "$@"
  fi
}

# --- 1. 바이너리 --------------------------------------------------------------
step "1/4 에이전트를 받는다"
case "$(uname -m)" in
  arm64)  ARCH="arm64" ;;
  x86_64) ARCH="amd64" ;;
  *) fail "지원하지 않는 아키텍처: $(uname -m)" ;;
esac
ASSET="edrdog-agent-darwin-$ARCH"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
curl -fsSL "$DOWNLOAD_BASE/$ASSET" -o "$TMP/agent" || fail "바이너리를 받지 못했다: $DOWNLOAD_BASE/$ASSET"

# 받은 것이 온전한지 본다. 끊긴 다운로드는 크기만 작고 그대로 실행돼서, 깔린 뒤에
# "왜 안 뜨지" 로 시간을 버리게 된다.
if curl -fsSL "$DOWNLOAD_BASE/$ASSET.sha256" -o "$TMP/want" 2>/dev/null; then
  # 파일 모양은 "<해시>  <파일명>" 이다. 해시는 첫 칸에 있다. 공백을 지우고 뒤에서 자르면
  # 파일명 끝을 해시로 읽는다(실제로 그렇게 짰다가 모든 설치가 막혔다).
  # \r 을 지우는 것은 파일이 CRLF 로 올라온 경우다.
  want="$(awk 'NR==1 {print $1}' "$TMP/want" | tr -d '\r')"
  got="$(shasum -a 256 "$TMP/agent" | awk '{print $1}')"
  # 64자 16진수가 아니면 비교 자체가 무의미하다. 그걸 "일치하지 않음" 으로 뭉뚱그리면
  # 릴리스 파일이 깨진 것과 바이너리가 바뀐 것을 구별할 수 없다.
  [[ "$want" =~ ^[A-Fa-f0-9]{64}$ ]] || fail "$ASSET.sha256 의 모양이 예상과 다르다: $want"
  [[ "$want" == "$got" ]] || fail "받은 바이너리의 해시가 다르다 (기대 $want, 실제 $got)"
  echo "해시 확인됨."
else
  # 릴리스에 해시 파일이 없을 수 있다. 그 사실을 조용히 넘기지는 않는다.
  echo "경고: $ASSET.sha256 이 없어 무결성을 확인하지 못했다" >&2
fi
install -m 755 "$TMP/agent" "$BIN_PATH"

# --- 2. 설정 ------------------------------------------------------------------
step "2/4 설정을 쓴다 ($SERVER)"
mkdir -p "$CONF_DIR"
chmod 755 "$CONF_DIR"
# 에이전트가 이 인증서로 서버를 고정한다. 여기서는 받아오기만 한다.
# 서버 인증서가 self-signed 라 openssl 은 받아 놓고도 검증 실패로 종료코드 1 을 낸다.
# pipefail 이 켜져 있어 그 코드를 그대로 믿으면 정상 수신도 실패로 끝난다. 파일로 판단한다.
openssl s_client -connect "$SERVER" -servername "${SERVER%%:*}" </dev/null 2>/dev/null \
  | sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' > "$CERT_PATH" || true
[[ -s "$CERT_PATH" ]] || fail "서버 인증서를 받지 못했다. $SERVER 가 열려 있는지 확인해라"
chmod 644 "$CERT_PATH"

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
  <key>StandardOutPath</key><string>$LOG_PATH</string>
  <key>StandardErrorPath</key><string>$LOG_PATH</string>
</dict>
</plist>
EOF
chmod 644 "$PLIST_PATH"
launchctl bootout system "$PLIST_PATH" 2>/dev/null || true
launchctl bootstrap system "$PLIST_PATH" || fail "LaunchDaemon 등록 실패"

# --- 3. 전체 디스크 접근 권한 --------------------------------------------------
step "3/4 전체 디스크 접근 권한"
cat <<EOF
이것만 사람이 해야 한다. 애플의 TCC 는 자동으로 켤 수 없다.
설정 창을 연다. 목록에서 '+' 를 누르고 아래 경로를 넣은 뒤 켜라.

    $BIN_PATH

파일 선택창이 뜬 다음에 Cmd+Shift+G 를 눌러야 경로 입력이 먹는다.
목록에 대고 바로 누르면 안 먹는다.
EOF
as_user open "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles" 2>/dev/null || true
read -rp $'\n켰으면 Enter. ' < /dev/tty

# --- 4. 확인 ------------------------------------------------------------------
step "4/4 재시작하고 확인한다"
# 지금까지의 로그는 이전 실행 것이다. 여기부터 새로 나온 줄만 본다.
before=0
[[ -f "$LOG_PATH" ]] && before="$(wc -l < "$LOG_PATH" | tr -d ' ')"
launchctl kickstart -k "system/$LABEL" || fail "재시작 실패"

for _ in $(seq 30); do
  sleep 1
  [[ -f "$LOG_PATH" ]] || continue
  # 로그가 잘렸으면 처음부터 다시 본다. 안 그러면 셀 자리가 파일 끝을 넘어서 새 줄을
  # 하나도 못 보고, 붙었는데도 시간초과로 끝난다.
  now="$(wc -l < "$LOG_PATH" | tr -d ' ')"
  (( now < before )) && before=0
  fresh="$(tail -n "+$((before + 1))" "$LOG_PATH" 2>/dev/null || true)"
  if grep -q "$DENIED_MARK" <<<"$fresh"; then
    echo
    echo "권한이 아직 없다. 전체 디스크 접근에서 $BIN_PATH 가 켜져 있는지 다시 봐라."
    echo "껐다 켜야 먹는 경우가 있다. 켠 뒤:  sudo launchctl kickstart -k system/$LABEL"
    exit 1
  fi
  if grep -q "$ENROLLED_MARK" <<<"$fresh"; then
    echo
    grep "$ENROLLED_MARK" <<<"$fresh" | tail -1
    echo
    echo "끝났다. 대시보드에 이 기기가 뜬다."
    echo "로그:  tail -f $LOG_PATH"
    exit 0
  fi
done

# 여기까지 왔다는 것은 둘 다 안 나왔다는 뜻이다. 성공으로 치지 않는다.
# LaunchDaemon 은 KeepAlive 라 서버에 못 붙어도 계속 살아 있다. 떠 있는 것만 보고
# 끝냈다고 하면 아무것도 안 오는 채로 설치가 끝난다.
echo
echo "30초 안에 등록 로그가 안 보인다. 아래를 직접 확인해라."
echo "  로그:   tail -n 50 $LOG_PATH"
echo "  상태:   sudo launchctl print system/$LABEL"
exit 1
