#!/usr/bin/env bash
# responder 실제 조치(#59)의 선결 확인: Fleet 이 우리가 쓰는 방식으로 동작하는지 실기 검증한다.
#   1) host 식별자 → Fleet 매핑이 되는지
#   2) scripts 실행이 이 호스트에서 가능한지 (fleetd 가 --enable-scripts 로 배포됐는지)
#   3) scripts 동기 실행 실제 지연 (= "수초냐" 의 실측값. Fleet 은 폴링이라 보통 수십초)
#
# fleetctl 로 호출한다(시스템 curl 의 LibreSSL 이 Fleet TLS 를 못 뚫는 문제 회피).
# responder 의 Java RestClient(JSSE)는 이 문제가 없으므로 코드와 무관하다.
#
# 전제: Fleet 기동(예: fleetctl preview) + fleetctl login + 테스트 호스트 등록.
#
# 사용:
#   ./scripts/fleet-verify.sh <host-식별자>
#   (host-식별자 = osquery 가 보고하는 hostname. detector 이벤트의 host 와 같아야 함)
set -euo pipefail

HOST="${1:?호스트 식별자 인자 필요 (hostname). 예: my-macbook.local}"
command -v fleetctl >/dev/null || { echo "fleetctl 필요 (npm i -g fleetctl 또는 brew install fleetctl)" >&2; exit 1; }

echo "== 1) host 식별자 → Fleet 매핑 =="
if fleetctl get host "${HOST}" >/dev/null 2>&1; then
  echo "  OK: '${HOST}' 조회됨"
else
  echo "  실패: '${HOST}' 못 찾음. 등록된 호스트 목록:"
  fleetctl get hosts || true
  exit 1
fi

echo "== 2)+3) scripts 동기 실행 + 지연 =="
SCRIPT="$(mktemp /tmp/edrdog-verify-XXXXXX.sh)"
trap 'rm -f "${SCRIPT}"' EXIT
printf '#!/bin/sh\necho EDRDOG_VERIFY_OK\n' > "${SCRIPT}"

START="$(date +%s)"
set +e
OUT="$(fleetctl run-script --host "${HOST}" --script-path "${SCRIPT}" 2>&1)"
set -e
END="$(date +%s)"

echo "  지연: $((END - START))s  (이 값이 '수초/수십초' 의 실측 답)"
echo "  결과: ${OUT}"
if echo "${OUT}" | grep -q EDRDOG_VERIFY_OK; then
  echo "  OK: 호스트에서 실제 실행됨 → responder 실행 경로 성립"
elif echo "${OUT}" | grep -qi 'disabled'; then
  echo "  막힘: 이 호스트의 fleetd 가 scripts 비활성."
  echo "        → fleetctl package ... --enable-scripts 로 만든 패키지로 재설치해야 함."
else
  echo "  주의: 예상 밖 결과(위 결과 참고). 호스트 오프라인/타임아웃 가능성."
fi
