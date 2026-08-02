# EDRdog 로컬 인프라 (k8s / kind)

모든 모듈의 전제. kind 클러스터에 Kafka(토픽 `events`/`alerts`) + ClickHouse + 모니터링 스택을 띄운다.
호스트에서 도는 Spring 서비스가 NodePort 매핑으로 접근한다.

## 기동

```bash
kind create cluster --config k8s/kind-cluster.yaml   # 클러스터 생성 (name: edrdog)
# kind-cluster.yaml 은 kind 전용이라 apply 대상에서 제외 (아래는 실제 매니페스트만)
kubectl apply -f k8s/00-namespace.yaml
# Grafana 로그인 비번. 없으면 otel-lgtm 파드가 안 뜬다 (로컬은 아무 값이나)
kubectl -n edrdog create secret generic edrdog-secrets --from-literal=GRAFANA_ADMIN_PASSWORD=admin
kubectl apply -f k8s/kafka.yaml -f k8s/clickhouse.yaml \
              -f k8s/otel-lgtm.yaml -f k8s/alloy.yaml
kubectl -n edrdog get pods                            # Running 확인
```

## 접속

| 대상 | 호스트 주소 | 비고 |
|---|---|---|
| Kafka | `localhost:9092` | detector 등 (EXTERNAL 리스너) |
| ClickHouse HTTP | `http://localhost:8123` | user/pw/db = `edrdog` |
| ClickHouse native | `localhost:9000` | JDBC/드라이버용 |
| Grafana | `http://localhost:3000` | `admin` / `GRAFANA_ADMIN_PASSWORD`. 첫 화면이 EDRdog Overview |
| OTLP HTTP | `http://localhost:4318` | 서비스가 메트릭·트레이스를 보내는 곳 |
| OTLP gRPC | `localhost:4317` | 〃 |
| 에이전트 수집 HTTPS | `localhost:8443` (NodePort 30443) | 엔드포인트 에이전트가 붙는 곳(collector-service). 아래 시크릿을 만들어야 열린다 |

클러스터 내부(파드 간) Kafka 주소: `kafka.edrdog.svc.cluster.local:9094`
클러스터 내부 OTLP 주소: `http://otel-lgtm:4318` (각 서비스 Deployment 의 `OTEL_EXPORTER_OTLP_ENDPOINT`)

## 확인

```bash
# 토픽 목록 (events / alerts 있어야 함)
kubectl -n edrdog exec deploy/kafka -- \
  /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9094 --list

# ClickHouse ping
curl http://localhost:8123/ping     # -> Ok.

# Grafana 헬스 + 대시보드 프로비저닝 확인 (EDRdog 폴더에 4개 있어야 함)
curl http://localhost:3000/api/health
curl "http://localhost:3000/api/search?type=dash-db"

# 로그 수집 확인 (수집 중인 서비스 목록)
curl "http://localhost:3000/api/datasources/proxy/uid/loki/loki/api/v1/label/service_name/values"
```

## 종료

```bash
kind delete cluster --name edrdog    # 클러스터째 삭제 (PVC 도 노드 안에 있어 함께 소멸)
```

## 에이전트 수집 포트 (collector-service 8443 / NodePort 30443)

에이전트는 서버 인증서를 고정해서 붙으므로 수집 경로에 HTTPS 가 필수다. 그래서 collector-service 는
내부 조회용 8082 와 별도로 에이전트 전용 HTTPS 커넥터를 8443 에 연다. **이 커넥터는 `agent-tls` Secret 이 있을 때만 켜진다**
(Secret 이 없으면 값이 안 들어와 `AGENT_TLS_ENABLED` 가 기본 false 로 남고, collector-service 는 그대로 정상 기동한다).

```bash
# 1) 서버 인증서 + 키스토어 생성. 인자는 엔드포인트가 실제로 붙을 주소(도메인 또는 공인 IP).
#    에이전트가 이 인증서를 고정하므로 SAN 이 접속 주소의 호스트와 같아야 한다.
#    인자가 IPv4 면 스크립트가 알아서 SAN 을 ip: 로 넣는다.
./scripts/gen-dev-keystore.sh ./dev-tls edrdog.example.com

# 2) Secret 생성 (키스토어 + 스위치 + 비번을 한 Secret 에)
kubectl -n edrdog create secret generic agent-tls \
  --from-file=keystore.p12=./dev-tls/agent-keystore.p12 \
  --from-literal=AGENT_TLS_ENABLED=true \
  --from-literal=AGENT_TLS_KEYSTORE_PASSWORD=changeit

kubectl -n edrdog rollout restart deploy/collector-service

# 3) 확인 (self-signed 라 -k)
curl -sk https://localhost:8443/api/agent/enroll -H 'Content-Type: application/json' \
  -d '{"enroll_secret":"틀린값"}'      # -> 401 + {"error":"invalid_enroll_secret"} 이면 커넥터 정상
```

엔드포인트에는 `./dev-tls/agent-server.pem` 을 배포하고 설정 파일을 맞춘다.
설치 스크립트를 쓰면 이 PEM 을 서버에서 직접 받아 오므로 파일을 따로 옮기지 않아도 된다
([`../agent/README.md`](../agent/README.md) 의 `설치`).

```json
{
  "base_url": "https://edrdog.example.com:30443",
  "ca_cert_path": "/etc/edrdog/server.pem"
}
```

- **Caddy 로 프록시하면 안 된다.** 에이전트가 설정에 적힌 인증서로 서버를 고정하기 때문에, 중간에서
  Caddy 가 TLS 를 다시 종단하면 에이전트가 보는 인증서는 Caddy 것이 된다. 고정한 것과 달라서 등록
  단계부터 붙지 못한다. 노출하려면 NodePort 30443 을 보안그룹에서 직접 열거나 L4(TCP) 통과 프록시를 쓴다.
- 인증서 SAN 이 `base_url` 의 호스트와 다르면 역시 등록 단계에서 실패한다. 주소가 바뀌면 인증서를
  다시 만들고 Secret 을 갱신한 뒤 엔드포인트의 PEM 까지 교체해야 한다.
### 매니페스트 변경을 배포서버에 반영하기

**인프라 매니페스트는 CD 가 알아서 올린다.** 목록을 적어 두지 않고 `k8s/` 를 훑어서 적용하므로,
파일을 새로 추가해도 워크플로를 같이 고칠 필요가 없다. 제외 대상은 셋뿐이다.

| 파일 | 왜 빼는가 |
|---|---|
| `*-service.yaml` | 이미지 태그를 끼워 넣어야 해서 바로 다음 단계에서 따로 apply 한다 |
| `kind-cluster.yaml` | 로컬 kind 설정이라 apply 대상이 아니다 |
| `infisical.yaml` | CRD 가 있을 때만 적용한다 |

인프라가 안 떠도 앱 배포는 막지 않고, 대신 CD 가 맨 끝에서 실패한다. `kafka-ui`·`portainer` 는
시크릿이 없으면 일부러 안 뜨는데 그것 때문에 앱 배포가 멈추면 곤란해서다.

**서비스 매니페스트도 CD 가 apply 한다.** 그래서 `env`·`envFrom`·probe·리소스를 고치면 머지만으로
서버에 반영된다. 예전에는 `set image` 만 해서 그런 변경이 영영 안 갔고, 머지도 CD 도 초록불인데
서버만 옛 설정으로 남았다(`archiver-service` 의 `envFrom` 이 이렇게 누락돼 CrashLoopBackOff 가 났다).

이미지 태그는 매니페스트의 `:latest` 를 쓰지 않고 CD 가 apply 직전에 갈아 끼운다.

| | 태그 |
|---|---|
| 이번 커밋에서 코드가 바뀐 모듈 | `:<sha>` (새로 구운 것) |
| 안 바뀐 모듈 | 지금 떠 있는 태그 그대로 |

두 번째가 필요한 이유는, 안 바꾼 모듈은 이미지를 굽지 않아서 그 커밋의 `:<sha>` 이미지가 GHCR 에
아예 없기 때문이다. 매니페스트만 고친 배포도 이 규칙 덕분에 롤아웃 없이 통과한다.

⚠️ **`:latest` 는 GHCR 에 올리지 않는다.** 매니페스트의 `:latest` 는 자리표시용이라 그대로 apply 하면
이미지를 못 받는다. 손으로 적용해야 하면 지금 떠 있는 태그를 끼워서 넣는다:

```bash
IMG=$(sudo kubectl -n edrdog get deploy/api-service -o jsonpath='{.spec.template.spec.containers[0].image}')
sed "s#^\( *\)image: ghcr.io/.*#\1image: $IMG#" k8s/api-service.yaml | sudo kubectl -n edrdog apply -f -
sudo kubectl -n edrdog rollout status deployment/api-service
```

Service 는 매니페스트가 서버 실제 상태(NodePort 30084)와 같아 apply 해도 그대로다.

### 롤백

이미지 태그가 커밋 `:<sha>` 라 되돌릴 지점이 명확하다. 직전 버전으로만 돌리면 되면:

```bash
sudo kubectl -n edrdog rollout undo deployment/api-service
sudo kubectl -n edrdog rollout status deployment/api-service
```

특정 커밋으로 찍어서 돌리려면(어느 리비전이 어느 이미지였는지 먼저 본다):

```bash
sudo kubectl -n edrdog rollout history deployment/api-service
sudo kubectl -n edrdog set image deployment/api-service api-service=ghcr.io/edrdog/backend/api-service:<되돌릴-sha>
```

⚠️ `set image` 로 돌린 것은 **다음 배포 때 매니페스트 apply 로 덮인다.** 임시 조치라는 뜻이고,
문제가 코드에 있으면 `main` 에서 revert 해서 정상 경로로 다시 배포해야 한다.

DB 스키마가 바뀐 릴리스는 이미지만 되돌려도 원상복구가 안 된다. ClickHouse 는 `CREATE TABLE IF NOT
EXISTS` + `ALTER` 로만 진화시키므로 컬럼이 늘어나는 방향은 안전하지만, 줄이는 변경은 롤백 계획을
따로 세운다.

- kind 로컬에서는 `kind-cluster.yaml` 의 `30443 -> hostPort 8443` 매핑을 쓴다.
  **`extraPortMappings` 는 클러스터 생성 시에만 반영**되므로 기존 클러스터라면 다시 만들거나
  `kubectl -n edrdog port-forward svc/collector-service-agent 8443:8443` 로 우회한다.

## GeoLite2 (위협 지도)

mmdb 는 이미지 안이 아니라 **호스트 디스크**에 둔다. `api-service` 가 `GEOIP_DB_PATH`
(`/etc/geoip/GeoLite2-Country.mmdb`, hostPath `/opt/edrdog/geoip`)를 먼저 읽고, 없으면 jar 번들로 넘어간다.

이렇게 하는 이유: MaxMind 는 하루 다운로드 한도가 있어 429 를 준다. 빌드가 mmdb 를 못 받으면
예전에는 빌드 전체가 멈춰 **배포가 통째로 막혔다**. 그렇다고 mmdb 없는 이미지를 올리면 위협 지도가
조용히 빈다. 파일을 호스트에 두면 이미지를 어떻게 갈아도 지도가 살아 있고, 빌드는 429 가 나도
경고만 남기고 지나간다.

파일 배치는 1회다. 지금 도는 파드의 jar 에서 꺼내 쓰면 새로 받을 필요가 없다.

```bash
# 1) 지금 도는 파드의 jar 에서 mmdb 를 꺼낸다 (컨테이너에 unzip 이 없으므로 jar 를 통째로 복사)
POD=$(sudo kubectl -n edrdog get pod -l app=api-service -o jsonpath='{.items[0].metadata.name}')
sudo kubectl -n edrdog cp "$POD:/app/app.jar" /tmp/api.jar
sudo mkdir -p /opt/edrdog/geoip
sudo unzip -p /tmp/api.jar BOOT-INF/classes/GeoLite2-Country.mmdb > /tmp/GeoLite2-Country.mmdb
sudo install -m 644 /tmp/GeoLite2-Country.mmdb /opt/edrdog/geoip/GeoLite2-Country.mmdb
rm -f /tmp/api.jar /tmp/GeoLite2-Country.mmdb

# 2) 크기가 0 이 아닌지 확인한다. 0 이면 그 이미지에 번들이 없던 것이다.
ls -l /opt/edrdog/geoip/GeoLite2-Country.mmdb

# 3) 매니페스트를 적용한다 (위 "매니페스트 변경을 배포서버에 반영하기" 와 같은 순서)
IMG=$(sudo kubectl -n edrdog get deploy/api-service -o jsonpath='{.spec.template.spec.containers[0].image}')
sed "s#^\( *\)image: ghcr.io/.*#\1image: $IMG#" k8s/api-service.yaml | sudo kubectl -n edrdog apply -f -
sudo kubectl -n edrdog rollout status deployment/api-service

# 4) 파일에서 읽었는지 로그로 확인한다
sudo kubectl -n edrdog logs deploy/api-service | grep 'GeoIP DB 로드'
```

4번이 `GeoIP DB 로드(파일)` 이면 성공이다. `(클래스패스)` 면 볼륨의 파일을 못 읽어 jar 번들로
넘어간 것이고, 그 상태로 mmdb 없는 이미지가 배포되면 지도가 빈다.

## 운영 UI (Portainer / Kafka UI / Grafana / Swagger)

배포서버 전용이다. 넷 다 Caddy 뒤에 있고 NodePort 를 방화벽에 열지 않으므로 Caddy 를 통해서만 들어간다.

| 대상 | 주소 | 인증 | Infisical 키 | NodePort |
|---|---|---|---|---|
| Portainer | `https://portainer.<도메인>` | 자체 로그인 (`admin`) | `PORTAINER_ADMIN_PASSWORD` | 30777 |
| Kafka UI | `https://<도메인>/kafka-ui` | 자체 로그인 폼 | `KAFKA_UI_USER` / `KAFKA_UI_PASSWORD` | 30901 |
| Grafana | `https://grafana.<도메인>` | 자체 로그인 (`admin`) | `GRAFANA_ADMIN_PASSWORD` | 30300 |
| Swagger | `https://<도메인>/swagger-ui.html` | Basic (`SwaggerAuthFilter`) | `EDRDOG_SWAGGER_USER` / `EDRDOG_SWAGGER_PASSWORD` | (api 30084) |

**Caddy 는 인증을 하지 않는다.** 넷 다 자기 안에서 막고 계정은 `edrdog-secrets` 에서 받는다. Caddy 에
basic auth 를 걸면 비번이 Infisical 과 호스트 파일 두 군데로 갈라지고, Infisical 에서 바꿔도 호스트의
Caddyfile 은 그대로라 반영되지 않는다.

**경로를 추가하거나 도메인을 바꿀 때는 `scripts/Caddyfile` 을 고친다.** 이 파일이 원본이고 CD 가
배포서버의 `/etc/caddy/Caddyfile` 로 넣는다(달라졌을 때만 `install` + `systemctl reload`). 서버에서 직접
고치면 다음 CD 가 덮어쓴다. 전에는 bootstrap 이 최초 1회 쓰고 아무도 다시 보지 않아서, 레포에 portainer
블록을 넣고도 서버는 모른 채였고 서브도메인이 인증서가 없어 TLS 핸드셰이크부터 깨졌다.

- **Kafka UI·Portainer·Grafana 는 키가 없으면 파드가 뜨지 않는다** (`optional` 을 안 줬다). 인증이 꺼진 채로
  멀쩡히 떠 있는 것보다 멈추는 편이 낫다. 키를 넣은 뒤
  `kubectl -n edrdog rollout restart deploy/kafka-ui deploy/portainer deploy/otel-lgtm`.
  `/kafka-ui/actuator/health` 와 Grafana `/api/health` 는 로그인 없이 200 이라 readinessProbe 는 그대로 통과한다.
- **Swagger 는 비번이 없으면 열리는 게 아니라 닫힌다.** `application.yml` 에 기본값을 두지 않았다.
  레포에 박아 두면 그게 곧 공개 비번이라서다. 로컬에서 보려면 `EDRDOG_SWAGGER_PASSWORD` 를 넣고 띄운다.
- Swagger 가 `ApiKeyPolicy` 의 인증 예외로 남아 있는 건 그대로다. 브라우저로 여는 화면이라 `X-API-Key`
  헤더를 붙일 수가 없어서, API 키 대신 Basic 으로 막는다.

### Portainer

`k8s/portainer.yaml`. `admin` / `PORTAINER_ADMIN_PASSWORD` 로 로그인한다. 계정은 `--admin-password-file` 로
파드가 뜨면서 자동 생성되므로 사람이 먼저 접속할 필요가 없다(원래는 5분 안에 안 만들면 스스로 잠근다).

- **`PORTAINER_ADMIN_PASSWORD` 는 첫 기동에만 먹는다.** Portainer 가 자기 DB(PVC)에 복사하기 때문에,
  계정이 생긴 뒤 Infisical 값을 바꿔도 비번은 안 바뀐다. 바꾸려면 Portainer UI 에서 바꾸거나 PVC 를 지운다.
  Kafka UI·Swagger 와 달리 Infisical 이 계속 진짜 소스인 구조가 아니다.
- 네임스페이스가 `portainer` 가 아니라 `edrdog` 인 이유: k8s Secret 은 네임스페이스를 넘지 못한다.
  `edrdog-secrets` 를 마운트하려면 같은 네임스페이스여야 한다.
- 이 계정은 `cluster-admin` 이라 `edrdog` 의 Secret(API 키, DB 비번)까지 전부 보인다. 비번을 세게 잡는다.
- 서브패스(`/portainer`)가 아니라 서브도메인인 이유: 서브패스로 서비스하려면 `--base-url` 과 프록시의
  prefix strip 이 정확히 한 번씩 맞아야 하고, 어긋나면 화면은 뜨는데 로그인이 안 된다.
- `--trusted-origins` 가 없으면 Caddy 뒤에서 로그인할 때 `Origin invalid` 로 막힌다. 도메인을 바꾸면
  매니페스트의 이 값도 같이 바꿔야 한다.
- 계정과 설정은 PVC 에 있다(k3s `local-path`). 지우면 다음 기동에서 Infisical 값으로 다시 만들어진다.

### Grafana

`k8s/otel-lgtm.yaml`. `admin` / `GRAFANA_ADMIN_PASSWORD` 로 로그인한다. 이미지 기본값이 **익명 Admin** 이라
(`run-grafana.sh` 가 `GF_AUTH_ANONYMOUS_ENABLED` 를 `true` 로 둔다) 그대로 밖에 열면 로그인 없이 아무나
로그·트레이스·메트릭을 다 보고 대시보드도 고친다. 그래서 `GF_AUTH_ANONYMOUS_ENABLED=false` 로 끄고
비번을 받는다.

- **이미 쓰던 PVC 에서는 `GRAFANA_ADMIN_PASSWORD` 가 안 먹는다.** `grafana.db` 가 `/data`(PVC) 에 있고
  Grafana 는 이 값을 **DB 가 없을 때만** 쓴다. 지금 서버의 DB 에는 기본 `admin` / `admin` 이 들어 있어서,
  익명만 끄고 끝내면 비번이 `admin` 인 채로 밖에 열리게 된다. 순서를 지켜야 한다.

  ```bash
  # 1) Infisical(prod)에 GRAFANA_ADMIN_PASSWORD 를 넣고 edrdog-secrets 를 갱신한다
  # 2) 지금 도는 파드에서 같은 값으로 비번을 바꾼다 (익명이 아직 켜져 있을 때 해 둔다)
  #    --homepath 는 conf/defaults.ini 가 있는 곳이고, DB 는 PVC 쪽이라 paths.data 를 따로 얹는다.
  #    /data/grafana 에는 data/ 만 있고 conf/ 가 없어서, 거기를 homepath 로 주면 기동부터 실패한다.
  sudo kubectl -n edrdog exec deploy/otel-lgtm -- \
    /otel-lgtm/grafana/bin/grafana cli \
      --homepath /otel-lgtm/grafana \
      --configOverrides cfg:default.paths.data=/data/grafana/data \
      admin reset-admin-password '<넣은-비번>'
  # 3) 그 다음 이 매니페스트를 배포한다 (CD 든 손이든)
  ```

  재시작은 필요 없다. 비번은 DB 에 바로 반영된다.

  순서를 뒤집으면 Grafana 가 뜰 때 자기 API 로 서비스 계정을 만드는 단계에서 비번이 안 맞아 401 이 난다
  (`run-all.sh` 가 `GF_SECURITY_ADMIN_USER`/`PASSWORD` 로 자기 API 를 호출한다).
- 대시보드는 ConfigMap 으로 프로비저닝되므로 PVC 를 지워도 다시 생긴다. 대신 지표·로그·트레이스 기록이
  통째로 날아가니 비번 때문에 PVC 를 지우지는 않는다.
- `GF_SERVER_ROOT_URL` 이 없으면 Grafana 가 만드는 절대 URL 이 `localhost:3000` 이 된다. 도메인을 바꾸면
  이 값과 `scripts/Caddyfile` 을 같이 바꾼다.

## 시크릿 (Infisical)

매니페스트에 평문으로 박혀 있던 값(`DB_PASSWORD`, `CLICKHOUSE_PASSWORD` 등)을 Infisical 로 옮긴다.
Operator 가 Infisical 을 읽어 `edrdog-secrets` k8s Secret 으로 동기화하고, 서비스는 그 Secret 을 `envFrom` 으로 받는다.

설치와 연결 절차는 `k8s/infisical.yaml` 주석에 있다. 요약하면 Operator 설치 1회,
Machine Identity 자격증명 Secret 생성 1회, `kubectl apply -f k8s/infisical.yaml`, 서비스에 `envFrom` patch.

- 실제로 도는 건 v1alpha1 `InfisicalSecret` 이다. 문서에 나오는 v1beta1 은 v0.11.6 부터 들어왔다.
- **Operator 이미지를 `:latest` 로 두지 않는다.** 설치 매니페스트 기본값이 `:latest` 라 Infisical 이 릴리스할 때마다
  서버가 조용히 갈아탄다. CRD 는 그대로인데 Operator 만 올라가면 시작하자마자 죽고(`no matches for kind
  "InfisicalConnection"`), 시크릿이 며칠씩 낡은 줄도 모르고 지나간다. 설치 뒤 반드시 태그를 고정한다:
  ```
  kubectl -n infisical-operator-system set image \
    deploy/infisical-operator-controller-manager manager=infisical/kubernetes-operator:v0.11.6
  ```
- Deployment 에 같은 이름의 env 가 직접 박혀 있으면 그쪽이 `envFrom` 을 이긴다. Infisical 값을 쓰려면
  `kubectl -n edrdog set env deployment/<이름> <키>-` 로 기존 env 를 먼저 지운다.
- CD 는 `infisicalsecrets` CRD 가 있을 때만 이 파일을 apply 한다. Operator 가 없으면 건너뛴다.

## 메모

- **MySQL·ClickHouse 는 PVC 를 쓴다.** 파드가 갈려도 가입 계정과 이벤트 이력이 남는다.
  볼륨이 없던 때는 노드 재부팅이나 OOM 한 번에 계정이 전부 사라져 로그인이 안 됐다.
  PVC 가 `ReadWriteOnce` 라 둘 다 `strategy: Recreate` 다. 롤링으로 두면 새 파드가 볼륨을 못 잡는다.
- **Kafka 는 영속성이 없다.** 남는 게 아직 소비 안 된 메시지뿐이고 토픽은 init Job 이 다시 만든다.
- ClickHouse `edrdog.events` **테이블은 archiver 부팅 시 자동 생성**(`CREATE TABLE IF NOT EXISTS`). 여기선 `edrdog` DB 만 준비.
- watchdog 클러스터와 호스트 포트(9092/8123/9000)가 겹치므로 **동시 실행 불가**.
- `extraPortMappings` 는 **클러스터 생성 시에만** 반영된다. 이미 만들어 둔 클러스터에 3000/4317/4318 을 뚫으려면
  클러스터를 다시 만들거나 `kubectl -n edrdog port-forward svc/otel-lgtm 3000:3000 4318:4318` 로 우회한다.

## 모니터링 (otel-lgtm)

- 구성: Grafana + Prometheus + Tempo + Loki 올인원 이미지(`grafana/otel-lgtm`) + 로그 수집기 Alloy(`k8s/alloy.yaml`).
- 신호별 경로
  - **메트릭**: api / detector / archiver 만 OTLP 로 전송 (`micrometer-registry-otlp` 를 그 3개 모듈 `build.gradle` 에만 추가)
  - **트레이스**: 6개 서비스 전부 OTLP 로 전송
  - **로그**: 앱은 그냥 stdout 에 찍고, Alloy 가 `*-service` 파드 로그를 읽어 Loki 로 보낸다 (앱 코드 변경 없음)
  - **인프라 메트릭**: Alloy 가 kubelet 의 cAdvisor·resource 엔드포인트를 긁어 컨테이너·노드 CPU/메모리를
    Prometheus 로 remote write 한다. 별도 exporter 를 띄우지 않는다.
- Kafka 발행·소비 구간에도 스팬이 생겨(`spring.kafka.*.observation-enabled`), collector → detector → archiver 흐름이
  트레이스 하나로 이어진다.
- 로그에는 Spring 기본 패턴의 `[traceId-spanId]` 를 Alloy 가 뽑아 structured metadata 로 붙인다.
  Grafana 에서 로그 한 줄을 펼치면 trace_id 링크로 Tempo 트레이스까지 바로 넘어간다.
- 대시보드는 **EDRdog 폴더에 4개**. 첫 화면은 Overview.

  | 대시보드 | 내용 |
  |---|---|
  | EDRdog Overview | 요청률·에러율·p95·컨슈머 랙 요약, 서비스별 트래픽, 힙, 로그 볼륨 |
  | EDRdog HTTP | 상태코드별 요청률, 분위(p50/95/99), 느린·많이 불린 엔드포인트 Top |
  | EDRdog Resources | 힙/GC/스레드/클래스, 컨슈머 랙·소비 처리량·커밋률, 컨테이너·노드 CPU/메모리 |
  | EDRdog Logs & Traces | 레벨별 로그 볼륨, 로그 스트림, 에러 로그, 최근 트레이스 목록 |

  이미지 기본 대시보드(RED / JVM Overview)도 루트에 그대로 남아 있다.
  대시보드를 고치려면 `otel-lgtm.yaml` ConfigMap 안의 JSON 을 고치고 apply 한 뒤 파드를 재시작한다
  (subPath 마운트라 ConfigMap 만 바꿔서는 반영되지 않는다).
- 스택 없이 서비스만 띄우려면 `OTEL_ENABLED=false`. 샘플링은 `OTEL_TRACE_SAMPLING`(기본 1.0 = 전량).
- 지표는 **PVC(`otel-lgtm-data`, 5Gi)** 에 남는다. 여기만 emptyDir 이 아니다. 파드가 재시작돼도 그동안의
  지표·로그·트레이스가 살아 있어야 발표 중에 그래프가 비지 않기 때문이다. 기본 StorageClass 를 쓴다.
  RWO 볼륨이라 Deployment 전략은 `Recreate`(롤링이면 새 파드가 볼륨을 못 잡고 서로 기다린다).
- **Grafana 는 로그인을 받는다** (`admin` / `GRAFANA_ADMIN_PASSWORD`). 이미지 기본값은 익명 Admin 이라
  포트에 닿는 사람 누구나 설정을 바꿀 수 있는데, 배포서버는 `https://grafana.<도메인>` 으로 밖에 열려
  있어서 껐다. 자세한 건 위 "운영 UI" 의 Grafana 절.
- **kind 로컬에서도 이 키가 필요하다.** 없으면 파드가 `CreateContainerConfigError` 로 멈춘다.
  로컬은 아무 값이나 넣으면 된다.

  ```bash
  kubectl -n edrdog create secret generic edrdog-secrets --from-literal=GRAFANA_ADMIN_PASSWORD=admin
  ```
