#!/usr/bin/env bash
# 오라클 클라우드 인스턴스 하나를 EDRdog 배포서버로 만든다.
#
# 새로 만든 인스턴스에서 한 번 돌린다. 여러 번 돌려도 안전하다(같은 것을 덮어쓴다).
#
#   sudo env DUCKDNS_TOKEN=... GHCR_USER=... GHCR_TOKEN=... \
#     AGENT_TLS_KEYSTORE_PASSWORD=... ./scripts/bootstrap-oracle.sh
#
# env 를 끼우는 이유: sudo VAR=값 명령 으로 쓰면 sudoers 의 NOPASSWD 가 적용되지 않아
# 비밀번호를 묻는다. 오라클 Ubuntu 이미지는 그 계정에 비밀번호가 없어서 답할 수가 없다.
#
# 하는 일:
#   1. 호스트 방화벽을 연다 (오라클은 이걸 안 하면 콘솔에서 열어도 막힌다)
#   2. k3s 를 깐다
#   3. DuckDNS 가 이 인스턴스의 공인 IP 를 가리키게 하고, 주기적으로 갱신한다
#   4. Caddy 를 깔고 도메인 블록을 쓴다
#   5. 에이전트 수집용 키스토어를 만들어 agent-tls Secret 으로 넣는다
#   6. GHCR 이미지를 받을 자격증명을 넣는다
#   7. edrdog-secrets 를 넣는다 (Infisical 에 로그인돼 있으면)
#   8. 인프라 매니페스트를 apply 한다
#
# 안 하는 일(사람이 해야 한다):
#   - 오라클 콘솔의 보안 목록(Security List) 에 80/443/30443 을 여는 것.
#     인스턴스 밖의 설정이라 여기서 건드릴 수 없다. 아래에서 다시 알려준다.
#   - Infisical 로그인. 로그인돼 있으면 edrdog-secrets 를 자동으로 넣고, 아니면 무엇이
#     안 뜨는지 알려준다.
set -euo pipefail

DOMAIN="${DOMAIN:-edrdog-api.duckdns.org}"
DUCKDNS_SUBDOMAIN="${DUCKDNS_SUBDOMAIN:-${DOMAIN%%.*}}"
NS="${NS:-edrdog}"
# sudo 로 돌면 HOME 이 /root 가 된다. 클론은 원래 사용자의 홈에 있으므로 그쪽을 본다.
SUDO_HOME="$(getent passwd "${SUDO_USER:-root}" 2>/dev/null | cut -d: -f6)"
REPO_DIR="${REPO_DIR:-${SUDO_HOME:-$HOME}/Backend}"
GHCR_IMAGE_BASE="${GHCR_IMAGE_BASE:-ghcr.io/edrdog/backend}"

# 에이전트가 붙는 포트. Caddy 를 거치지 않는다. 에이전트가 서버 인증서를 고정해서 붙기
# 때문에 중간에서 TLS 를 다시 종단하면 등록 단계에서 실패한다.
AGENT_PORT=30443
API_NODEPORT=30084
KAFKA_UI_NODEPORT=30901
PORTAINER_NODEPORT=30777

fail() { echo "오류: $*" >&2; exit 1; }
step() { echo; echo "== $*"; }

[[ "$(id -u)" == "0" ]] || fail "sudo 로 실행해야 한다"

for v in DUCKDNS_TOKEN GHCR_USER GHCR_TOKEN AGENT_TLS_KEYSTORE_PASSWORD; do
  [[ -n "${!v:-}" ]] || fail "$v 가 필요하다"
done

# 여기서 안 짚으면 나중에 파드가 exec format error 로만 죽는다.
ARCH="$(uname -m)"
step "0/8 확인 (arch=$ARCH)"
case "$ARCH" in
  aarch64) echo "  Ampere A1(arm64) 이다. 이미지가 arm64 를 포함해야 한다." ;;
  x86_64)  echo "  x86_64 다." ;;
  *) fail "지원하지 않는 아키텍처: $ARCH" ;;
esac

# --- 1. 호스트 방화벽 ---------------------------------------------------------
# 오라클 이미지는 INPUT 사슬 끝에 REJECT 가 박힌 채로 나온다. 콘솔의 보안 목록만 열고
# 여기를 안 열면 밖에서는 그냥 타임아웃으로 보인다. 원인을 짚기 가장 어려운 자리다.
step "1/8 호스트 방화벽을 연다"
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
step "2/8 k3s"
# traefik 을 끄고 깐다. k3s 는 기본으로 traefik 을 깔고 그게 호스트 80/443 을 잡는데,
# 그러면 Caddy 가 "address already in use" 로 못 뜬다. 우리는 Caddy 로 프록시한다.
if command -v k3s >/dev/null 2>&1; then
  echo "  이미 깔려 있다."
else
  curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--disable=traefik" sh - || fail "k3s 설치 실패"
fi
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
# 이미 깔린 뒤에 이 스크립트를 돌리는 경우가 있다. 그때도 traefik 은 걷어낸다.
if kubectl -n kube-system get helmchart traefik >/dev/null 2>&1; then
  echo "  traefik 을 걷어낸다 (Caddy 와 80/443 을 다툰다)"
  kubectl -n kube-system delete helmchart traefik traefik-crd --ignore-not-found >/dev/null
  kubectl -n kube-system delete deploy traefik --ignore-not-found >/dev/null
fi
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
kubectl get nodes >/dev/null || fail "k3s 가 응답하지 않는다"
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

# --- 3. DuckDNS ---------------------------------------------------------------
step "3/8 DuckDNS ($DOMAIN)"
duck_update() {
  curl -sS "https://www.duckdns.org/update?domains=$DUCKDNS_SUBDOMAIN&token=$DUCKDNS_TOKEN&ip="
}
result="$(duck_update)"
[[ "$result" == "OK" ]] || fail "DuckDNS 갱신 실패: $result"
echo "  갱신됨."

# 인스턴스를 껐다 켜면 공인 IP 가 바뀐다.
cat > /usr/local/bin/duckdns-update <<EOF
#!/bin/sh
curl -sS "https://www.duckdns.org/update?domains=$DUCKDNS_SUBDOMAIN&token=$DUCKDNS_TOKEN&ip=" >/dev/null
EOF
chmod 700 /usr/local/bin/duckdns-update   # 토큰이 들어 있다
echo '*/5 * * * * root /usr/local/bin/duckdns-update' > /etc/cron.d/duckdns
echo "  5분마다 갱신하도록 걸었다."

# --- 4. Caddy -----------------------------------------------------------------
step "4/8 Caddy"
# 80 을 다른 웹서버가 잡고 있으면 Caddy 가 "address already in use" 로 못 뜬다.
# 실제 인스턴스에 nginx 가 올라와 있었다. 그 상태로는 아래 restart 가 조용히 실패한다.
for other in nginx apache2 httpd; do
  if systemctl is-active --quiet "$other" 2>/dev/null; then
    echo "  $other 가 80 을 잡고 있어 내린다"
    systemctl disable --now "$other" >/dev/null 2>&1 || true
  fi
done
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

# 도메인 블록 안에서 벗은 reverse_proxy 와 handle 은 섞을 수 없다. 처음부터 전부 감싼다.
#
# Caddy 는 인증을 하지 않는다. 운영 UI 세 개가 각자 자기 로그인을 갖고 있고, 그 계정은
# Infisical 이 넣는다(Kafka UI 는 AUTH_TYPE=LOGIN_FORM, Swagger 는 api-service 의
# SwaggerAuthFilter, Portainer 는 자체 로그인). 여기서 또 막으면 비번이 두 군데로 갈라지고,
# Infisical 에서 비번을 바꿔도 호스트의 이 파일은 그대로라 반영이 안 된다.
cat > /etc/caddy/Caddyfile <<EOF
$DOMAIN {
	handle /kafka-ui* {
		reverse_proxy localhost:$KAFKA_UI_NODEPORT
	}
	handle {
		reverse_proxy localhost:$API_NODEPORT
	}
}

# Portainer. DuckDNS 는 하위 도메인이 전부 같은 IP 로 오므로 레코드를 따로 만들 필요가 없고,
# Caddy 가 이 이름으로 인증서를 알아서 받는다(80 이 열려 있어야 받는다).
portainer.$DOMAIN {
	reverse_proxy localhost:$PORTAINER_NODEPORT
}
EOF
# 설정이 틀리면 reload 가 조용히 실패하고 사이트가 옛 설정으로 남거나 죽는다. 여기서 잡는다.
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1 \
  || fail "Caddyfile 이 잘못됐다: caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile"
systemctl enable --now caddy >/dev/null 2>&1 || true
systemctl reload caddy 2>/dev/null || systemctl restart caddy
echo "  $DOMAIN -> localhost:$API_NODEPORT"
echo "  portainer.$DOMAIN -> localhost:$PORTAINER_NODEPORT"

# --- 5. 에이전트 수집 TLS -----------------------------------------------------
# 에이전트가 호스트명을 SAN 과 대조한다. 도메인을 바꾸면 여기도 다시 만들어야 한다.
step "5/8 agent-tls"
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

# 이름이 agent-tls 여야 한다. 매니페스트가 optional:true 로 참조해서, 틀리면 커넥터가
# 꺼진 채로 파드는 멀쩡히 뜬다. 정상으로 보이는데 에이전트만 못 붙는다.
kubectl -n "$NS" delete secret agent-tls --ignore-not-found >/dev/null
kubectl -n "$NS" create secret generic agent-tls \
  --from-file=keystore.p12="$TLS_DIR/agent-keystore.p12" \
  --from-literal=AGENT_TLS_ENABLED=true \
  --from-literal=AGENT_TLS_KEYSTORE_PASSWORD="$AGENT_TLS_KEYSTORE_PASSWORD" >/dev/null
echo "  SAN=dns:$DOMAIN"

# --- 6. GHCR 자격증명 ---------------------------------------------------------
# GHCR 패키지는 기본이 비공개다. 이게 없으면 파드가 ImagePullBackOff 로 멈춘다.
step "6/8 GHCR 자격증명"
kubectl -n "$NS" delete secret ghcr --ignore-not-found >/dev/null
kubectl -n "$NS" create secret docker-registry ghcr \
  --docker-server=ghcr.io \
  --docker-username="$GHCR_USER" \
  --docker-password="$GHCR_TOKEN" >/dev/null
# default 서비스어카운트에 붙여 두면 매니페스트마다 imagePullSecrets 를 적지 않아도 된다.
kubectl -n "$NS" patch serviceaccount default \
  -p '{"imagePullSecrets":[{"name":"ghcr"}]}' >/dev/null
echo "  default 서비스어카운트에 붙였다."

# --- 7. edrdog-secrets --------------------------------------------------------
# api / collector / responder 가 envFrom 으로 이걸 요구한다. 없으면 셋 다
# CreateContainerConfigError 로 멈춘다. 그런데 alert / detector / archiver 는 참조하지 않아
# 멀쩡히 뜬다. 절반만 도는 그 모습이 원인을 짚기 가장 어렵다. 실제로 여기서 배포가 막혔다.
step "7/8 edrdog-secrets"
if kubectl -n "$NS" get secret edrdog-secrets >/dev/null 2>&1; then
  echo "  이미 있다."
elif command -v infisical >/dev/null 2>&1 && infisical export --env=prod --format=dotenv >/dev/null 2>&1; then
  infisical export --env=prod --format=dotenv \
    | kubectl -n "$NS" create secret generic edrdog-secrets --from-env-file=/dev/stdin \
        --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  echo "  Infisical 에서 받아 넣었다."
else
  # 여기서 끝내지 않는다. 나머지는 다 해 놓고 무엇이 안 되는지만 정확히 알려주는 편이 낫다.
  MISSING_SECRET=1
  echo "  못 만들었다. api / collector / responder 가 뜨지 않는다." >&2
fi

# --- 8. 인프라 매니페스트 -----------------------------------------------------
step "8/8 인프라 매니페스트"
if [[ -d "$REPO_DIR/.git" ]]; then
  git -C "$REPO_DIR" fetch --quiet origin main || true
  for f in k8s/00-namespace.yaml k8s/mysql.yaml k8s/kafka.yaml k8s/clickhouse.yaml \
           k8s/otel-lgtm.yaml k8s/alloy.yaml k8s/kafka-ui.yaml k8s/portainer.yaml; do
    git -C "$REPO_DIR" show "FETCH_HEAD:$f" | kubectl apply -f - >/dev/null && echo "  $f"
  done
else
  echo "  $REPO_DIR 에 레포 클론이 없어 건너뛴다." >&2
  echo "  git clone https://github.com/EDRdog/Backend.git $REPO_DIR 뒤에 다시 돌려라." >&2
fi

if [[ "${MISSING_SECRET:-0}" == "1" ]]; then
  cat >&2 <<EOF

먼저 할 것: edrdog-secrets 가 없다.

  이게 없으면 api / collector / responder 가 안 뜬다. alert / detector / archiver 는
  참조하지 않아 멀쩡히 뜨므로, 절반만 도는 모습이 된다.

  서버에서 Infisical 에 로그인한 뒤 이 스크립트를 다시 돌리면 자동으로 만든다.

    curl -1sLf 'https://artifacts-cli.infisical.com/setup.deb.sh' | sudo -E bash
    sudo apt-get update -qq && sudo apt-get install -y infisical
    infisical login --interactive
    cd ~ && infisical init

  직접 넣으려면(있으면 갱신, 없으면 생성):

    infisical export --env=prod --format=dotenv \\
      | kubectl -n $NS create secret generic edrdog-secrets --from-env-file=/dev/stdin \\
          --dry-run=client -o yaml | kubectl apply -f -
EOF
fi

cat <<EOF

준비 끝. 남은 것은 사람이 해야 한다.

1) 오라클 콘솔에서 포트를 연다 (인스턴스 밖 설정이라 여기서 못 한다)
   네트워킹 > 가상 클라우드 네트워크 > 서브넷 > 보안 목록 > 수신 규칙 추가
     0.0.0.0/0  TCP  80
     0.0.0.0/0  TCP  443
     0.0.0.0/0  TCP  $AGENT_PORT      <- 에이전트가 붙는 포트

2) main 에 푸시한다
   CD 가 arm64 를 포함해 이미지를 올리고, 서비스 매니페스트 apply 와 롤아웃까지 한다.
   Deployment 가 없으면 CD 가 알아서 apply 하므로 여기서 손으로 할 것은 없다.

3) Infisical 에 운영 UI 계정을 넣는다 (prod 환경)
     KAFKA_UI_USER / KAFKA_UI_PASSWORD              <- Kafka UI 로그인
     EDRDOG_SWAGGER_USER / EDRDOG_SWAGGER_PASSWORD  <- Swagger 로그인
     PORTAINER_ADMIN_PASSWORD                       <- Portainer 관리자 (아이디는 admin 고정)
   넣은 뒤 edrdog-secrets 를 다시 만든다(위 7단계의 명령). 그리고:
     kubectl -n $NS rollout restart deploy/kafka-ui deploy/portainer
   kafka-ui 와 portainer 는 이 키가 없으면 파드가 뜨지 않는다. 인증이 꺼진 채로 떠 있으면
   토픽 메시지가 그대로 공개돼서, 멈추는 편이 낫다고 보고 일부러 그렇게 뒀다.
   Swagger 는 비번이 없으면 열리는 게 아니라 닫힌다.
   PORTAINER_ADMIN_PASSWORD 는 첫 기동에만 먹는다. 계정이 생긴 뒤에 바꾸려면 Portainer UI 에서 바꾼다.

4) 확인
   kubectl -n $NS get pods
   curl -sS https://$DOMAIN/actuator/health
   curl -sS -o /dev/null -w '%{http_code}\n' https://$DOMAIN/kafka-ui/          # -> 302 (로그인으로)
   curl -sS -o /dev/null -w '%{http_code}\n' https://$DOMAIN/swagger-ui.html    # -> 401
   curl -sS -o /dev/null -w '%{http_code}\n' https://portainer.$DOMAIN/api/users/admin/check  # -> 204 (계정 생성됨)
   openssl s_client -connect $DOMAIN:$AGENT_PORT </dev/null 2>/dev/null | head -3

   Portainer 는 admin / PORTAINER_ADMIN_PASSWORD 로 로그인한다.
   이 계정은 cluster-admin 이라 edrdog 의 Secret 까지 다 보인다. 비번을 세게 잡는다.

kubectl 을 그냥 쓰려면:
   echo 'export KUBECONFIG=/etc/rancher/k3s/k3s.yaml' >> ~/.bashrc
EOF
