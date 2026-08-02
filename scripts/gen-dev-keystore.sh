#!/usr/bin/env bash
# 에이전트 수집 HTTPS(dev)용 self-signed 키스토어와, 에이전트가 고정할 서버 cert(PEM)를 생성한다.
# 에이전트는 평문 HTTP 로 붙지 않으므로 로컬 e2e 테스트에도 HTTPS 가 필요하다.
#
# 사용:
#   ./scripts/gen-dev-keystore.sh [출력디렉토리] [호스트명]
#   AGENT_TLS_KEYSTORE_PASSWORD=... ./scripts/gen-dev-keystore.sh ./dev-tls localhost
#
# 산출물:
#   <out>/agent-keystore.p12  → collector-service AGENT_TLS_KEYSTORE 로 지정
#   <out>/agent-server.pem    → 에이전트 설정의 ca_cert_path 로 지정(인증서 고정)
set -euo pipefail

OUT="${1:-./dev-tls}"
HOST="${2:-localhost}"
PASS="${AGENT_TLS_KEYSTORE_PASSWORD:-changeit}"
ALIAS="${AGENT_TLS_KEY_ALIAS:-agent}"

mkdir -p "$OUT"

# 에이전트는 접속 주소의 호스트를 서버 인증서의 SAN 과 대조한다. 배포 주소가 IP 면 dns: 로 넣어봐야 검증에 실패하므로 IPv4 는 ip: 로 넣는다.
if [[ "$HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  SAN="ip:$HOST,ip:127.0.0.1"
else
  SAN="dns:$HOST,ip:127.0.0.1"
fi

keytool -genkeypair -alias "$ALIAS" -keyalg RSA -keysize 2048 -validity 825 \
  -dname "CN=$HOST" -ext "SAN=$SAN" \
  -keystore "$OUT/agent-keystore.p12" -storetype PKCS12 \
  -storepass "$PASS" -keypass "$PASS"

keytool -exportcert -alias "$ALIAS" -rfc \
  -keystore "$OUT/agent-keystore.p12" -storepass "$PASS" \
  -file "$OUT/agent-server.pem"

echo
echo "생성 완료:"
echo "  keystore : $OUT/agent-keystore.p12  (비번: $PASS, alias: $ALIAS)"
echo "  server cert(PEM) : $OUT/agent-server.pem"
echo
echo "collector-service 기동 예:"
echo "  AGENT_TLS_ENABLED=true \\"
echo "  AGENT_TLS_KEYSTORE=$OUT/agent-keystore.p12 \\"
echo "  AGENT_TLS_KEYSTORE_PASSWORD=$PASS \\"
echo "  ./gradlew :collector-service:bootRun"
echo
echo "k8s(collector-service) 에 태우려면 Secret 하나 만들면 끝(만들기 전엔 커넥터 OFF):"
echo "  kubectl -n edrdog create secret generic agent-tls \\"
echo "    --from-file=keystore.p12=$OUT/agent-keystore.p12 \\"
echo "    --from-literal=AGENT_TLS_ENABLED=true \\"
echo "    --from-literal=AGENT_TLS_KEYSTORE_PASSWORD=$PASS"
echo "  kubectl -n edrdog rollout restart deploy/collector-service"
echo
echo "에이전트 설정(config.json) 에는 이렇게 넣는다:"
echo "  \"base_url\": \"https://$HOST:30443\","
echo "  \"ca_cert_path\": \"$OUT/agent-server.pem\""
