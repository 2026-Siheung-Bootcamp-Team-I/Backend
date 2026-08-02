# collector (에이전트 수집 입구)

에이전트의 HTTP 를 직접 받는 서비스다. 인증하고, 조직 태그를 붙이고, 검증해서 통과한 것만
`events` 로 발행한다.

```
Go Agent ──HTTPS(enroll/heartbeat/events/command-result)──▶ collector ──▶ [events] ──▶ detector / archiver
(엔드포인트)                                                인증·tenant태깅·검증        검증 통과분
```

## 왜 이 자리로 옮겼나

예전에는 api-service 가 에이전트를 받아 `events-raw` 로 흘리고 collector 가 그걸 소비해 검증했다.
그 중간 홉이 사라졌다. 수집 경로는 프론트 API 와 트래픽 성격도, 죽었을 때 파장도 다르다.
프론트 조회가 몰려 api-service 가 흔들릴 때 엔드포인트 수집까지 같이 멈추는 게 가장 나쁜 조합이었다.

검증 경계라는 성격은 그대로다. 들어오는 값은 **엔드포인트에서 온 입력**이고, 망가진 이벤트가
detector 까지 흘러가면 판정이 오염된다.

## 인증

| 경로 | 인증 |
|:---|:---|
| `POST /api/agent/enroll` | `enroll_secret` (api-service 에 물어봐 tenant 를 푼다) |
| `POST /api/agent/heartbeat` `/events` `/command-result` | `X-Node-Key` 헤더 |
| `GET /api/internal/nodes?tenantId=` | `X-Internal-Key` 헤더 (서비스 간 조회) |

실패는 전부 401 이다. 200 본문에 실패를 담지 않는다. 에이전트는 401 을 받으면 저장한 node_key 를
버리고 다시 등록한다. 서버가 키를 잃어도 사람이 손대지 않고 복구되어야 하기 때문이다.

**node_key 는 해시(SHA-256 hex)로만 저장한다.** 발급한 평문은 enroll 응답으로만 나간다. DB 가 새도
그 값으로는 엔드포인트를 위장할 수 없다. BCrypt 를 쓰지 않는 이유는 node_key 가 32바이트
SecureRandom 이라 사전공격 대상이 아니고, 매 요청 인증에 태우면 heartbeat/events 가 그만큼
느려지기 때문이다.

평문을 저장하지 않으니 재-enroll 때 기존 토큰을 돌려줄 방법이 없다. 그래서 같은 host 가 다시
등록하면 노드는 하나로 유지하되 **토큰은 새로 발급**한다.

## 검증 규칙 ([`RawEventMapper`](src/main/java/com/edrdog/collectorservice/RawEventMapper.java))

| 조건 | 처리 |
|:---|:---|
| JSON 이 깨졌거나 객체가 아님 | 스킵 |
| `host` 가 비어 있음 | 스킵. 상관분석 키가 없으면 쓸모가 없다 |
| `type` 이 `process`/`network`/`file`/`script`/`dns`/`l7` 이 아님 | 스킵. 모르는 타입을 `process` 로 넘겨짚지 않는다 |
| `ts` 가 없거나 0 이하 | 스킵 |
| `ts` 가 `100000000000` 미만 | 스킵. 초 단위를 밀리초로 착각해 보낸 값이다 |
| `type` 이 `network` 인데 `destIp` 가 비어 있음 | 스킵 |
| `type` 이 `dns`/`l7` 인데 `domain` 이 비어 있음 | 스킵 |
| `sha256` 이 64자리 16진수가 아님 | 그 필드만 빈 값. 이벤트는 살린다 |

- 통과한 이벤트는 **값을 그대로 옮긴다.** basename 추출, 타입 추측, 시각 변환은 하지 않는다.
  그 일은 에이전트가 한다. 경로 구분자가 플랫폼마다 다르니 그 플랫폼에서 도는 쪽이
  판단하는 게 맞다
- `ts` 와 `destPort` 는 숫자로 와도 문자열로 와도 받는다
- **검증 실패는 버리되 건수를 로그에 남긴다.** 한 건이 이상하다고 요청 전체를 실패시키면
  같은 배치의 정상 이벤트까지 못 받는다
- `tenantId` 는 에이전트가 보낸 값을 믿지 않고 node_key 로 푼 값으로 덮어쓴다
  ([`EventTagger`](src/main/java/com/edrdog/collectorservice/agent/EventTagger.java))

응답의 `accepted` 는 **실제로 `events` 에 발행된 건수**다. 발행할 때 **`host` 를 파티션 키로 쓴다.**
한 기기의 이벤트가 한 파티션에 모여야 detector 상관분석에서 순서가 보존된다.

## 엔드포인트 설치

에이전트 빌드·설정·설치와 알려진 한계는 [`../agent/README.md`](../agent/README.md) 에 있다.
서버와의 계약은 [`../docs/agent-protocol.md`](../docs/agent-protocol.md) 다.

## 실행

전제: [`../k8s/README.md`](../k8s/README.md) 로 Kafka 기동 (토픽 `events`/`alerts` 생성됨).
등록 노드를 저장할 MySQL(`edrdog_collector`)과 enroll secret 을 풀어 줄 api-service 도 필요하다.

에이전트는 서버 인증서를 고정하므로 수집 경로에는 HTTPS 가 필수다. dev 는 self-signed 키스토어를
만들어 에이전트 전용 커넥터(8443)를 연다. 내부용 HTTP 8082 와는 별도 포트다.

```bash
# 1) self-signed 키스토어 + 에이전트가 고정할 서버 cert(PEM) 생성
./scripts/gen-dev-keystore.sh ./dev-tls localhost

# 2) collector 기동 (HTTPS 커넥터 켜기)
AGENT_TLS_ENABLED=true \
AGENT_TLS_KEYSTORE=./dev-tls/agent-keystore.p12 \
AGENT_TLS_KEYSTORE_PASSWORD=changeit \
API_URL=http://localhost:8084 \
./gradlew :collector-service:bootRun

# 3) enroll secret 발급: 프론트 로그인 후 아래를 호출해 나온 값을 엔드포인트에 심는다.
#    POST {api-service}/api/tenant/enroll-secret  → { "enrollSecret": "..." }
```

에이전트 설정 파일에는 `ca_cert_path` 로 `./dev-tls/agent-server.pem` 을 지정하고, `enroll_secret`
에 발급받은 값을 넣는다. 인증서 SAN 이 `base_url` 의 호스트와 다르면 등록 단계에서 실패한다.

## 수집 경로 검증 (센서 권한 없이)

에이전트 권한 문제와 서버 배선 문제를 분리하는 방법이 둘 있다.

**하나. 에이전트의 `-selftest`.** 커널을 건드리지 않고 네 타입의 가짜 이벤트를 보낸다.
대시보드까지 올라오면 등록·인증서 고정·전송·검증·판정 경로가 전부 살아 있다는 뜻이다.
자세한 내용은 [`../agent/README.md`](../agent/README.md).

**둘. 에이전트 없이 API 를 직접 호출.** 서버 쪽만 볼 때 쓴다.

```bash
# collector 기동 상태에서. enroll secret 은 위 `실행` 3)에서 발급.
SECRET=<발급받은 enroll secret>
KEY=$(curl -sk https://localhost:8443/api/agent/enroll -H 'Content-Type: application/json' \
  -d "{\"enroll_secret\":\"$SECRET\",\"host_identifier\":\"mac-001\",\"platform\":\"darwin\"}" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["node_key"])')

# 이벤트 1건 주입 → tenant 태깅·검증 후 events 발행
curl -sk https://localhost:8443/api/agent/events \
  -H 'Content-Type: application/json' -H "X-Node-Key: $KEY" \
  -d '{"events":[{"host":"mac-001","type":"process","ts":1785341400000,"process":"bash","parent":"zsh","cmdline":"bash -c whoami"}]}'
# 기대: {"accepted":1}

# events 에서 확인
kubectl -n edrdog exec deploy/kafka -- /opt/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server localhost:9094 --topic events --from-beginning --max-messages 1
# 기대: {"host":"mac-001","type":"process","ts":1785341400000,"process":"bash","parent":"zsh","cmdline":"bash -c whoami","destIp":null,"destPort":0,"domain":null,"detail":null,"sha256":null,"tenantId":"<tenant>"}
```

검증 규칙이 실제로 거르는지 보려면 `ts` 를 초 단위(`1785341400`)로 바꿔 같은 요청을 보낸다.
`accepted` 가 `0` 이 되고 `events` 에는 아무것도 나오지 않아야 한다.

## 룰 검증 (Atomic Red Team)

검증 경로까지 확인되면 실제 악성행위를 재현해 detector 룰을 본다. (실제 호스트에서 수동 실행)

```bash
Invoke-AtomicTest T1059.001            # Windows PowerShell
# macOS 는 osascript/bash 계열 원자 테스트 사용
```

실행 후 `events` → `alerts` 흐름과 detector 판정 로그를 확인한다.

## 한계 (알려진 것)

- **버린 이벤트는 건수만 남는다.** 어떤 필드가 어긋났는지는 남기지 않는다. 지금 규모에서는
  이벤트 원문을 로그에 흘리는 비용이 이득보다 크다고 봤다
- **에이전트가 보낸 값의 내용은 검증하지 않는다.** `host` 가 비지 않았는지만 보고 그 기기가 정말
  그 이름인지는 따지지 않는다. 조직 격리는 `tenantId` 로 하고 그 값은 서버가 node_key 로 푼다
- **enroll 은 api-service 에 의존한다.** 그쪽이 죽어 있으면 새 엔드포인트를 등록할 수 없다.
  이미 등록된 엔드포인트의 heartbeat/events 는 node_key 로만 끝나므로 영향이 없다
- 엔드포인트 쪽 한계(macOS 네트워크 폴링, Windows 실기기 미검증 등)는
  [`../agent/README.md`](../agent/README.md) 의 `알려진 한계` 에 정리해 두었다
