#!/usr/bin/env bash
# osquery 수집 HTTPS(dev)용 self-signed 키스토어와, osquery 가 핀할 서버 cert(PEM)를 생성한다.
# osquery TLS logger 는 평문 HTTP 로 붙지 않으므로 로컬 e2e 테스트에도 HTTPS 가 필요하다.
#
# 사용:
#   ./scripts/gen-dev-keystore.sh [출력디렉토리] [호스트명]
#   OSQUERY_TLS_KEYSTORE_PASSWORD=... ./scripts/gen-dev-keystore.sh ./dev-tls localhost
#
# 산출물:
#   <out>/osquery-keystore.p12  → api-service OSQUERY_TLS_KEYSTORE 로 지정
#   <out>/osquery-server.pem    → osquery --tls_server_certs 로 핀
set -euo pipefail

OUT="${1:-./dev-tls}"
HOST="${2:-localhost}"
PASS="${OSQUERY_TLS_KEYSTORE_PASSWORD:-changeit}"
ALIAS="${OSQUERY_TLS_KEY_ALIAS:-osquery}"

mkdir -p "$OUT"

# osquery 는 --tls_hostname 의 호스트를 서버 인증서의 SAN 과 대조한다.
# 배포 주소가 IP 면 dns: 로 넣어봐야 검증에 실패하므로 IPv4 는 ip: 로 넣는다.
if [[ "$HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  SAN="ip:$HOST,ip:127.0.0.1"
else
  SAN="dns:$HOST,ip:127.0.0.1"
fi

keytool -genkeypair -alias "$ALIAS" -keyalg RSA -keysize 2048 -validity 825 \
  -dname "CN=$HOST" -ext "SAN=$SAN" \
  -keystore "$OUT/osquery-keystore.p12" -storetype PKCS12 \
  -storepass "$PASS" -keypass "$PASS"

keytool -exportcert -alias "$ALIAS" -rfc \
  -keystore "$OUT/osquery-keystore.p12" -storepass "$PASS" \
  -file "$OUT/osquery-server.pem"

echo
echo "생성 완료:"
echo "  keystore : $OUT/osquery-keystore.p12  (비번: $PASS, alias: $ALIAS)"
echo "  server cert(PEM) : $OUT/osquery-server.pem"
echo
echo "api-service 기동 예:"
echo "  OSQUERY_TLS_ENABLED=true \\"
echo "  OSQUERY_TLS_KEYSTORE=$OUT/osquery-keystore.p12 \\"
echo "  OSQUERY_TLS_KEYSTORE_PASSWORD=$PASS \\"
echo "  ./gradlew :api-service:bootRun"
echo
echo "k8s(api-service) 에 태우려면 Secret 하나 만들면 끝(만들기 전엔 커넥터 OFF):"
echo "  kubectl -n edrdog create secret generic osquery-tls \\"
echo "    --from-file=keystore.p12=$OUT/osquery-keystore.p12 \\"
echo "    --from-literal=OSQUERY_TLS_ENABLED=true \\"
echo "    --from-literal=OSQUERY_TLS_KEYSTORE_PASSWORD=$PASS"
echo "  kubectl -n edrdog rollout restart deploy/api-service"
echo
echo "osquery 엔드포인트 플래그: collector-service/osquery/osquery.mac.flags · osquery.win.flags"
echo "  (--tls_server_certs 를 $OUT/osquery-server.pem 로 지정, --tls_hostname 은 $HOST:30443)"
