#!/usr/bin/env bash
# EDRdog 에이전트를 macOS 에 명령 하나로 올린다.
#
# install-macos.sh 는 설치만 한다. 그 앞뒤로 사람이 손으로 하던 것들이 있었다.
# 시크릿을 curl 로 받고, 빌드하고, 설치하고, 시스템 설정을 뒤져 권한을 켜고, 재시작하고,
# 로그를 봐서 붙었는지 확인하는 순서다. 이 스크립트가 그걸 전부 잇는다.
#
# 사용:
#   sudo ./bootstrap-macos.sh --server <호스트:포트> --enroll-secret <값>
#   sudo ./bootstrap-macos.sh --server <호스트:포트> --email <메일> --api-key <키>
#
# 두 번째 형태는 로그인해서 시크릿을 대신 받아 온다. 비밀번호는 인자로 받지 않고 물어본다.
# 인자로 주면 ps 에 그대로 보이고 셸 기록에도 남는다.
#
# 전체 디스크 접근 권한만은 여기서도 못 켠다. Apple 의 TCC 는 사람이 직접 켜거나 MDM
# 프로파일로만 줄 수 있다. 대신 그 설정 창을 열어 주고, 켤 때까지 기다렸다가 이어서 한다.
set -euo pipefail

SERVER=""
ENROLL_SECRET=""
EMAIL=""
API_KEY=""
BINARY=""

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN_PATH="/usr/local/bin/edrdog-agent"
LOG_PATH="/var/log/edrdog/agent.log"
LABEL="com.edrdog.agent"

# 등록에 성공하면 에이전트가 남기는 줄(main.go). 이 줄이 떠야 서버까지 붙은 것이다.
ENROLLED_MARK="등록 완료"
# 권한이 없으면 eslogger 가 이 오류를 낸다. 붙었는지 아닌지보다 이 쪽이 더 흔한 실패다.
DENIED_MARK="ERR_NOT_PERMITTED"

fail() { echo "오류: $*" >&2; exit 1; }
step() { echo; echo "== $*"; }

# json_string 은 값 하나를 JSON 문자열로 감싼다.
# 비밀번호에 " 나 \ 가 들어 있으면 그냥 이어 붙인 본문은 깨진 JSON 이 되고, 서버는 그걸
# 로그인 실패로 돌려준다. 비밀번호가 맞는데 안 되는 것만큼 붙잡기 어려운 것이 없다.
json_string() {
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  printf '"%s"' "$s"
}

# json_field 는 평평한 JSON 응답에서 문자열 필드 하나를 꺼낸다.
#
# 콜론 둘레의 공백을 허용한다. 지금 서버(Jackson)는 공백 없이 내보내지만, 그 가정을 박아
# 두면 앞에 프록시가 하나 끼어 본문을 다시 찍는 순간 값이 조용히 빈 문자열이 된다.
# 빈 값은 아래에서 fail 로 걸러지긴 해도, 이유가 "응답에 토큰이 없다" 로 보여서 엉뚱한 데를
# 뒤지게 된다.
json_field() {
  sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server)        SERVER="${2:-}"; shift 2 ;;
    --enroll-secret) ENROLL_SECRET="${2:-}"; shift 2 ;;
    --email)         EMAIL="${2:-}"; shift 2 ;;
    --api-key)       API_KEY="${2:-}"; shift 2 ;;
    --binary)        BINARY="${2:-}"; shift 2 ;;
    *) fail "모르는 인자: $1" ;;
  esac
done

[[ "$(id -u)" == "0" ]] || fail "sudo 로 실행해야 한다"
[[ -n "$SERVER" ]] || fail "--server <호스트:포트> 가 필요하다"
# 비밀번호를 묻고, 권한을 켤 때까지 기다린다. 사람이 앞에 없으면 둘 다 못 한다.
# 여기서 먼저 걸러야 설치를 반쯤 해 놓고 죽지 않는다.
[[ -r /dev/tty ]] || fail "터미널에서 직접 실행해야 한다 (권한 승인을 기다려야 한다)"

# sudo 로 도는 중이라 빌드와 GUI 조작은 원래 사용자로 되돌려서 한다.
# root 로 빌드하면 Go 모듈 캐시에 root 소유 파일이 섞여 다음 빌드가 권한 오류로 죽는다.
RUN_AS="${SUDO_USER:-}"
as_user() {
  if [[ -n "$RUN_AS" && "$RUN_AS" != "root" ]]; then
    sudo -u "$RUN_AS" "$@"
  else
    "$@"
  fi
}

# --- 1. enroll secret ---------------------------------------------------------
if [[ -z "$ENROLL_SECRET" ]]; then
  [[ -n "$EMAIL" ]] || fail "--enroll-secret 을 주거나, --email 과 --api-key 로 받아 오게 해라"
  [[ -n "$API_KEY" ]] || fail "--api-key 가 필요하다 (/api/tenant 는 X-API-Key 예외 경로가 아니다)"

  step "1/5 로그인해서 enroll secret 을 받는다 ($EMAIL)"
  # 비밀번호는 화면에 찍지 않는다.
  read -rsp "비밀번호: " PASSWORD < /dev/tty
  echo
  [[ -n "$PASSWORD" ]] || fail "비밀번호가 비었다"

  login_body="$(printf '{"email":%s,"password":%s}' \
    "$(json_string "$EMAIL")" "$(json_string "$PASSWORD")")"

  TOKEN="$(curl -fsS -X POST "https://$SERVER/api/auth/login" \
    -H 'Content-Type: application/json' -d "$login_body" \
    | json_field token)" || fail "로그인 실패"
  [[ -n "$TOKEN" ]] || fail "로그인 응답에 토큰이 없다"

  ENROLL_SECRET="$(curl -fsS -X POST "https://$SERVER/api/tenant/enroll-secret" \
    -H "Authorization: Bearer $TOKEN" -H "X-API-Key: $API_KEY" \
    | json_field enrollSecret)" || fail "enroll secret 발급 실패"
  [[ -n "$ENROLL_SECRET" ]] || fail "응답에 enrollSecret 이 없다"
  echo "받았다."
else
  step "1/5 건너뜀 (enroll secret 을 직접 받았다)"
fi

# --- 2. 빌드 ------------------------------------------------------------------
if [[ -z "$BINARY" ]]; then
  BINARY="$HERE/edrdog-agent"
  step "2/5 에이전트를 빌드한다"
  command -v go >/dev/null || fail "go 가 없다. 이미 만든 바이너리가 있으면 --binary <경로> 로 줘라"
  # env -C 를 안 쓰는 이유는 그게 오래된 macOS 의 env 에는 없어서다. go 의 -C 는 1.20 부터
  # 있고, 어차피 go 가 있어야 여기까지 온다.
  as_user go build -C "$HERE/.." -o "$BINARY" ./cmd/edrdog-agent || fail "빌드 실패"
else
  step "2/5 건너뜀 (바이너리를 직접 받았다: $BINARY)"
fi

# --- 3. 설치 ------------------------------------------------------------------
step "3/5 설치한다"
"$HERE/install-macos.sh" --server "$SERVER" --enroll-secret "$ENROLL_SECRET" --binary "$BINARY"

# --- 4. 전체 디스크 접근 권한 --------------------------------------------------
step "4/5 전체 디스크 접근 권한"
cat <<EOF
설정 창을 연다. 목록에서 '+' 를 누르고 아래 경로를 넣은 뒤 켜라.

    $BIN_PATH

파일 선택창이 뜬 다음에 Cmd+Shift+G 를 눌러야 경로 입력이 먹는다.
목록에 대고 바로 누르면 안 먹는다.
EOF
as_user open "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles" 2>/dev/null || true
read -rp $'\n켰으면 Enter. ' < /dev/tty

# --- 5. 재시작하고 붙었는지 본다 ------------------------------------------------
step "5/5 재시작하고 확인한다"
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
    echo "끝났다. 대시보드에 이 호스트가 뜬다."
    echo "로그:  tail -f $LOG_PATH"
    exit 0
  fi
done

# 여기까지 왔다는 것은 둘 다 안 나왔다는 뜻이다. 성공으로 치지 않는다.
echo
echo "30초 안에 등록 로그가 안 보인다. 아래를 직접 확인해라."
echo "  로그:   tail -n 50 $LOG_PATH"
echo "  상태:   sudo launchctl print system/$LABEL"
echo "  서버:   curl -sk https://$SERVER/actuator/health"
exit 1
