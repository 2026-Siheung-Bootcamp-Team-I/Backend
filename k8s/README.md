# EDRdog 로컬 인프라 (k8s / kind)

모든 모듈의 전제. kind 클러스터에 Kafka(토픽 `events`/`alerts`) + ClickHouse + 모니터링 스택을 띄운다.
호스트에서 도는 Spring 서비스가 NodePort 매핑으로 접근한다.

## 기동

```bash
kind create cluster --config k8s/kind-cluster.yaml   # 클러스터 생성 (name: edrdog)
# kind-cluster.yaml 은 kind 전용이라 apply 대상에서 제외 (아래는 실제 매니페스트만)
kubectl apply -f k8s/00-namespace.yaml -f k8s/kafka.yaml -f k8s/clickhouse.yaml \
              -f k8s/otel-lgtm.yaml -f k8s/alloy.yaml
kubectl -n edrdog get pods                            # Running 확인
```

## 접속

| 대상 | 호스트 주소 | 비고 |
|---|---|---|
| Kafka | `localhost:9092` | detector 등 (EXTERNAL 리스너) |
| ClickHouse HTTP | `http://localhost:8123` | user/pw/db = `edrdog` |
| ClickHouse native | `localhost:9000` | JDBC/드라이버용 |
| Grafana | `http://localhost:3000` | admin / admin. 첫 화면이 EDRdog Overview |
| OTLP HTTP | `http://localhost:4318` | 서비스가 메트릭·트레이스를 보내는 곳 |
| OTLP gRPC | `localhost:4317` | 〃 |

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
kind delete cluster --name edrdog    # 클러스터째 삭제 (데이터 emptyDir 라 함께 소멸)
```

## 메모

- 개발용이라 **영속성 없음**(emptyDir). 파드 재시작 시 데이터 소멸.
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
- Kafka 발행·소비 구간에도 스팬이 생겨(`spring.kafka.*.observation-enabled`), api → collector → detector → archiver 흐름이
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
- **Grafana 는 비번 없이 들어가진다.** otel-lgtm 이미지가 익명 접속을 Admin 권한으로 열어두기 때문이다
  (`GF_AUTH_ANONYMOUS_ENABLED=true`, `GF_AUTH_ANONYMOUS_ORG_ROLE=Admin`). 데모용으로 편한 대신,
  포트에 닿는 사람은 누구나 설정을 바꿀 수 있다. 오래 띄워둘 거면 이 두 env 를 Deployment 에서 꺼야 한다.
