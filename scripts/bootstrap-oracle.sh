#!/usr/bin/env bash
# 오라클 클라우드 인스턴스 하나를 EDRdog 배포서버로 만든다.
#
# 새로 만든 인스턴스에서 한 번 돌린다. 여러 번 돌려도 안전하다(같은 것을 덮어쓴다).
#
#   sudo DUCKDNS_TOKEN=... GHCR_USER=... GHCR_TOKEN=... \
#     AGENT_TLS_KEYSTORE_PASSWORD=... ./scripts/bootstrap-oracle.sh
#
# 하는 일:
#   1. 호스트 방화벽을 연다 (오라클은 이걸 안 하면 콘솔에서 열어도 막힌다)
#   2. k3s 를 깐다
#   3. DuckDNS 가 이 인스턴스의 공인 IP 를 가리키게 하고, 주기적으로 갱신한다
#   4. Caddy 를 깔고 도메인 블록을 쓴다
#   5. 에이전트 수집용 키스토어를 만들어 agent-tls Secret 으로 넣는다
#   6. GHCR 이미지를 받을 자격증명을 넣는다
#   7. 인프라 매니페스트를 apply 한다
#
# 안 하는 일(사람이 해야 한다):
#   - 오라클 콘솔의 보안 목록(Security List) 에 80/443/30443 을 여는 것.
#     인스턴스 밖의 설정이라 여기서 건드릴 수 없다. 아래에서 다시 알려준다.
#   - 서비스 매니페스트 apply. 이미지가 GHCR 에 올라간 뒤에 해야 한다(맨 아래 안내).
set -euo pipefail

DOMAIN="${DOMAIN:-edrdog-api.duckdns.org}"
DUCKDNS_SUBDOMAIN="${DUCKDNS_SUBDOMAIN:-${DOMAIN%%.*}}"
NS="${NS:-edrdog}"
REPO_DIR="${REPO_DIR:-$HOME/Backend}"
GHCR_IMAGE_BASE="${GHCR_IMAGE_BASE:-ghcr.io/edrdog/backend}"

# 에이전트가 붙는 포트. Caddy 를 거치지 않는다. 에이전트가 서버 인증서를 고정해서 붙기
# 때문에 중간에서 TLS 를 다시 종단하면 등록 단계에서 실패한다.
AGENT_PORT=30443
API_NODEPORT=30084

fail() { echo "오류: $*" >&2; exit 1; }
step() { echo; echo "== $*"; }

[[ "$(id -u)" == "0" ]] || fail "sudo 로 실행해야 한다"

for v in DUCKDNS_TOKEN GHCR_USER GHCR_TOKEN AGENT_TLS_KEYSTORE_PASSWORD; do
  [[ -n "${!v:-}" ]] || fail "$v 가 필요하다"
done

# 아키텍처를 먼저 본다. 여기서 짚어 주지 않으면 나중에 파드가 exec format error 로만
# 죽는데, 그 메시지로는 원인이 아키텍처라는 것을 알기 어렵다.
ARCH="$(uname -m)"
step "0/7 확인 (arch=$ARCH)"
case "$ARCH" in
  aarch64) echo "  Ampere A1(arm64) 이다. 이미지가 arm64 를 포함해야 한다." ;;
  x86_64)  echo "  x86_64 다." ;;
  *) fail "지원하지 않는 아키텍처: $ARCH" ;;
esac

# --- 1. 호스트 방화벽 ---------------------------------------------------------
# 오라클 이미지는 INPUT 사슬 끝에 REJECT 가 박힌 채로 나온다. 콘솔의 보안 목록만 열고
# 여기를 안 열면 밖에서는 그냥 타임아웃으로 보인다. 원인을 짚기 가장 어려운 자리다.
step "1/7 호스트 방화벽을 연다"
open_port() {
  local port=$1 proto=${2:-tcp}
  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="$port/$proto" >/dev/null
  else
    # 이미 있으면 넣지 않는다(-C 로 확인). 여러 번 돌려도 규칙이 쌓이지 않게.
    iptables -C INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null \
      || iptables -I INPUT 1 -p "$proto" --dport "$port" -j ACCEPT
  fi
  echo "  $port/$proto"
}
open_port 80
open_port 443
open_port "$AGENT_PORT"

if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  firewall-cmd --reload >/dev/null
else
  # 규칙을 저장하지 않으면 재부팅 때 사라진다. 그러면 어느 날 갑자기 안 붙는다.
  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null
  else
    DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent >/dev/null 2>&1 \
      && netfilter-persistent save >/dev/null \
      || echo "  경고: 규칙을 저장하지 못했다. 재부팅하면 사라진다" >&2
  fi
fi

# --- 2. k3s -------------------------------------------------------------------
step "2/7 k3s"
if command -v k3s >/dev/null 2>&1; then
  echo "  이미 깔려 있다."
else
  curl -sfL https://get.k3s.io | sh - || fail "k3s 설치 실패"
fi
# 이 뒤로 kubectl 을 쓰려면 kubeconfig 가 필요하다.
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
kubectl get nodes >/dev/null || fail "k3s 가 응답하지 않는다"
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

# --- 3. DuckDNS ---------------------------------------------------------------
step "3/7 DuckDNS ($DOMAIN)"
duck_update() {
  curl -sS "https://www.duckdns.org/update?domains=$DUCKDNS_SUBDOMAIN&token=$DUCKDNS_TOKEN&ip="
}
result="$(duck_update)"
[[ "$result" == "OK" ]] || fail "DuckDNS 갱신 실패: $result"
echo "  갱신됨."

# 공인 IP 가 바뀌면(인스턴스를 껐다 켜면 바뀔 수 있다) 도메인이 엉뚱한 곳을 가리킨다.
# 5분마다 갱신해 둔다.
cat > /usr/local/bin/duckdns-update <<EOF
#!/bin/sh
curl -sS "https://www.duckdns.org/update?domains=$DUCKDNS_SUBDOMAIN&token=$DUCKDNS_TOKEN&ip=" >/dev/null
EOF
chmod 700 /usr/local/bin/duckdns-update   # 토큰이 들어 있다
echo '*/5 * * * * root /usr/local/bin/duckdns-update' > /etc/cron.d/duckdns
echo "  5분마다 갱신하도록 걸었다."

# --- 4. Caddy -----------------------------------------------------------------
step "4/7 Caddy"
if ! command -v caddy >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl >/dev/null
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
      | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
      > /etc/apt/sources.list.d/caddy-stable.list
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y caddy >/dev/null
  else
    dnf install -y 'dnf-command(copr)' >/dev/null && dnf copr enable -y @caddy/caddy >/dev/null && dnf install -y caddy >/dev/null
  fi
fi

# 도메인 블록 안에서는 벗은 reverse_proxy 와 handle 을 섞을 수 없다. 라우트를 늘릴 것을
# 생각해 처음부터 전부 handle 로 감싼다. 나중에 하나 추가하려다 기존 것까지 고치게 된다.
cat > /etc/caddy/Caddyfile <<EOF
$DOMAIN {
	handle /kafka-ui* {
		reverse_proxy localhost:30901
	}
	handle {
		reverse_proxy localhost:$API_NODEPORT
	}
}
EOF
systemctl enable --now caddy >/dev/null 2>&1 || true
systemctl reload caddy 2>/dev/null || systemctl restart caddy
echo "  $DOMAIN -> localhost:$API_NODEPORT"

# --- 5. 에이전트 수집 TLS -----------------------------------------------------
# 에이전트는 RootCAs 만 갈아끼우고 InsecureSkipVerify 를 쓰지 않는다. 그래서 접속 주소의
# 호스트가 인증서 SAN 과 같아야 한다. 도메인을 바꾸면 여기도 다시 만들어야 한다.
step "5/7 agent-tls"
command -v keytool >/dev/null 2>&1 || {
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y openjdk-21-jre-headless >/dev/null
  else
    dnf install -y java-21-openjdk-headless >/dev/null
  fi
}
TLS_DIR=/etc/edrdog/agent-tls
mkdir -p "$TLS_DIR"
rm -f "$TLS_DIR/agent-keystore.p12"
keytool -genkeypair -alias agent -keyalg RSA -keysize 2048 -validity 825 \
  -dname "CN=$DOMAIN" -ext "SAN=dns:$DOMAIN,ip:127.0.0.1" \
  -keystore "$TLS_DIR/agent-keystore.p12" -storetype PKCS12 \
  -storepass "$AGENT_TLS_KEYSTORE_PASSWORD" -keypass "$AGENT_TLS_KEYSTORE_PASSWORD" >/dev/null
chmod 600 "$TLS_DIR/agent-keystore.p12"

# 이름이 agent-tls 여야 한다. 매니페스트가 optional:true 로 참조해서, 이름이 틀리면
# 값이 안 들어오고 커넥터가 꺼진 채로 api-service 는 멀쩡히 뜬다. 파드는 정상인데
# 에이전트만 한 대도 못 붙는 상태가 되는데, 그 조합이 가장 짚기 어렵다.
kubectl -n "$NS" delete secret agent-tls --ignore-not-found >/dev/null
kubectl -n "$NS" create secret generic agent-tls \
  --from-file=keystore.p12="$TLS_DIR/agent-keystore.p12" \
  --from-literal=AGENT_TLS_ENABLED=true \
  --from-literal=AGENT_TLS_KEYSTORE_PASSWORD="$AGENT_TLS_KEYSTORE_PASSWORD" >/dev/null
echo "  SAN=dns:$DOMAIN"

# --- 6. GHCR 자격증명 ---------------------------------------------------------
# GHCR 패키지는 기본이 비공개다. 이게 없으면 파드가 ImagePullBackOff 로 멈춘다.
step "6/7 GHCR 자격증명"
kubectl -n "$NS" delete secret ghcr --ignore-not-found >/dev/null
kubectl -n "$NS" create secret docker-registry ghcr \
  --docker-server=ghcr.io \
  --docker-username="$GHCR_USER" \
  --docker-password="$GHCR_TOKEN" >/dev/null
# default 서비스어카운트에 붙여 두면 매니페스트마다 imagePullSecrets 를 적지 않아도 된다.
kubectl -n "$NS" patch serviceaccount default \
  -p '{"imagePullSecrets":[{"name":"ghcr"}]}' >/dev/null
echo "  default 서비스어카운트에 붙였다."

# --- 7. 인프라 매니페스트 -----------------------------------------------------
step "7/7 인프라 매니페스트"
if [[ -d "$REPO_DIR/.git" ]]; then
  git -C "$REPO_DIR" fetch --quiet origin main || true
  for f in k8s/00-namespace.yaml k8s/mysql.yaml k8s/kafka.yaml k8s/clickhouse.yaml \
           k8s/otel-lgtm.yaml k8s/alloy.yaml k8s/kafka-ui.yaml; do
    git -C "$REPO_DIR" show "FETCH_HEAD:$f" | kubectl apply -f - >/dev/null && echo "  $f"
  done
else
  echo "  $REPO_DIR 에 레포 클론이 없어 건너뛴다." >&2
  echo "  git clone https://github.com/EDRdog/Backend.git $REPO_DIR 뒤에 다시 돌려라." >&2
fi

cat <<EOF

준비 끝. 남은 것은 사람이 해야 한다.

1) 오라클 콘솔에서 포트를 연다 (인스턴스 밖 설정이라 여기서 못 한다)
   네트워킹 > 가상 클라우드 네트워크 > 서브넷 > 보안 목록 > 수신 규칙 추가
     0.0.0.0/0  TCP  80
     0.0.0.0/0  TCP  443
     0.0.0.0/0  TCP  $AGENT_PORT      <- 에이전트가 붙는 포트

2) 이미지를 GHCR 에 올린다
   레포를 옮기면서 패키지가 따라오지 않아 지금 $GHCR_IMAGE_BASE 는 비어 있다.
   main 에 푸시하면 CD 가 빌드해서 올린다. arm64 를 포함해 올라간다.

3) 서비스 매니페스트를 apply 한다 (이미지가 올라간 뒤에)
   for f in k8s/{detector,responder,archiver,api,alert,collector}-service.yaml; do
     git -C $REPO_DIR show "FETCH_HEAD:\$f" | kubectl apply -f -
   done

4) 확인
   kubectl -n $NS get pods
   curl -sS https://$DOMAIN/actuator/health
   openssl s_client -connect $DOMAIN:$AGENT_PORT </dev/null 2>/dev/null | head -3

kubectl 을 그냥 쓰려면:
   echo 'export KUBECONFIG=/etc/rancher/k3s/k3s.yaml' >> ~/.bashrc
EOF
