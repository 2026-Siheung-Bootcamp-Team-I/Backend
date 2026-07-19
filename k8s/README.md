# EDRdog 로컬 인프라 (k8s / kind)

모든 모듈의 전제. kind 클러스터에 Kafka(토픽 `events`/`alerts`) + ClickHouse 를 띄운다.
호스트에서 도는 Spring 서비스가 NodePort 매핑으로 접근한다.

## 기동

```bash
kind create cluster --config k8s/kind-cluster.yaml   # 클러스터 생성 (name: edrdog)
# kind-cluster.yaml 은 kind 전용이라 apply 대상에서 제외 (아래는 실제 매니페스트만)
kubectl apply -f k8s/00-namespace.yaml -f k8s/kafka.yaml -f k8s/clickhouse.yaml
kubectl -n edrdog get pods                            # Running 확인
```

## 접속

| 대상 | 호스트 주소 | 비고 |
|---|---|---|
| Kafka | `localhost:9092` | detector 등 (EXTERNAL 리스너) |
| ClickHouse HTTP | `http://localhost:8123` | user/pw/db = `edrdog` |
| ClickHouse native | `localhost:9000` | JDBC/드라이버용 |

클러스터 내부(파드 간) Kafka 주소: `kafka.edrdog.svc.cluster.local:9094`

## 확인

```bash
# 토픽 목록 (events / alerts 있어야 함)
kubectl -n edrdog exec deploy/kafka -- \
  /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9094 --list

# ClickHouse ping
curl http://localhost:8123/ping     # -> Ok.
```

## 종료

```bash
kind delete cluster --name edrdog    # 클러스터째 삭제 (데이터 emptyDir 라 함께 소멸)
```

## 메모

- 개발용이라 **영속성 없음**(emptyDir). 파드 재시작 시 데이터 소멸.
- ClickHouse **테이블 스키마는 이후 이슈**에서 (여기선 `edrdog` DB 만 준비).
- watchdog 클러스터와 호스트 포트(9092/8123/9000)가 겹치므로 **동시 실행 불가**.
