#!/usr/bin/env bash
# 엔드포인트에 붙여넣을 설치 명령을 만든다.
#
#   ./scripts/install-link.sh me@example.com
#
# 로그인해서 설치 링크를 받는 것까지 한 번에 한다. 대시보드에 "기기 추가" 버튼이 생기면 그쪽이 이 자리를 대신한다(그때까지 쓰는 것).
#
# 받는 쪽은 아무것도 다루지 않는다. 나온 한 줄을 붙여넣으면 끝난다.
set -euo pipefail

SERVER="${SERVER:-https://edrdog-api.duckdns.org}"
EMAIL="${1:-}"

fail() { echo "오류: $*" >&2; exit 1; }

[[ -n "$EMAIL" ]] || fail "사용법: $0 <이메일>   (서버를 바꾸려면 SERVER=https://... )"
[[ -r /dev/tty ]] || fail "비밀번호를 물어야 해서 터미널에서 실행해야 한다"

# 값에 " 나 \ 가 들어 있으면 그냥 이어 붙인 본문은 깨진 JSON 이 되고, 서버는 그걸 로그인 실패로 돌려준다(비밀번호가 맞는데 안 되는 것만큼 붙잡기 어려운 게 없다).
json_string() {
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  printf '"%s"' "$s"
}

# 콜론 둘레의 공백을 허용한다. 지금 서버(Jackson)는 공백 없이 내보내지만, 앞에 프록시가 끼어 본문을 다시 찍으면 값이 조용히 빈 문자열이 된다.
json_field() {
  sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p"
}

read -rsp "비밀번호: " PASSWORD < /dev/tty
echo
[[ -n "$PASSWORD" ]] || fail "비밀번호가 비었다"

TOKEN="$(curl -fsS -X POST "$SERVER/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d "$(printf '{"email":%s,"password":%s}' "$(json_string "$EMAIL")" "$(json_string "$PASSWORD")")" \
  | json_field token)" || fail "로그인 실패"
[[ -n "$TOKEN" ]] || fail "로그인 응답에 토큰이 없다"

# X-API-Key 를 안 보낸다. 이 경로는 Bearer 로만 인증한다(ApiKeyPolicy.EXEMPT_PATHS).
RESPONSE="$(curl -fsS -X POST "$SERVER/api/tenant/install-link" \
  -H "Authorization: Bearer $TOKEN")" || fail "설치 링크 발급 실패"

MACOS="$(json_field macosCommand <<<"$RESPONSE")"
WINDOWS="$(json_field windowsCommand <<<"$RESPONSE")"
EXPIRES="$(json_field expiresAt <<<"$RESPONSE")"
[[ -n "$MACOS" ]] || fail "응답에 설치 명령이 없다: $RESPONSE"

cat <<EOF

macOS — 터미널에 붙여넣는다:

  $MACOS

Windows — 관리자 권한 PowerShell 에 붙여넣는다:

  $WINDOWS

이 링크는 $EXPIRES 까지 쓸 수 있고, 그 안에는 여러 대에 써도 된다.
EOF
