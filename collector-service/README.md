# collector (에이전트 이벤트 검증 경계)

에이전트가 보낸 이벤트를 detector 에 넘기기 전에 거르는 서비스다.
`events-raw` 를 소비해 검증하고, 통과한 것만 `events` 로 재발행한다.

```
에이전트 ──HTTPS(enroll/heartbeat/events)──▶ api-service ──▶ [events-raw] ──▶ collector ──▶ [events] ──▶ detector / archiver
(엔드포인트)                                  인증·tenant태깅    조직 태그만 붙은 이벤트   검증        검증 통과분
```

## 왜 남겨 두었나

예전에는 이 서비스가 osquery 의 원시 result-log 에서 껍데기를 벗기는 일을 했다. `columns` 중첩을
풀고, `hostIdentifier` 와 `unixTime` 을 꺼내고, 초를 밀리초로 바꾸고, 쿼리 이름으로 타입을 넘겨짚고,
경로에서 파일명을 뽑았다. 수집기를 직접 만들면서 그 변환은 전부 사라졌다. 에이전트가 detector 가
쓰는 스키마 그대로 보내기 때문이다. **벗길 껍데기가 없다.**

그래도 서비스를 없애지 않은 이유는 하나다. `events-raw` 에 들어오는 값은 **엔드포인트에서 온
입력**이다. 망가진 이벤트가 detector 까지 흘러가면 판정이 오염된다. 변환 레이어가 아니라
검증 경계로 자리를 바꿔서 남겼다.

## 검증 규칙 ([`RawEventMapper`](src/main/java/com/edrdog/collectorservice/RawEventMapper.java))

| 조건 | 처리 |
|:---|:---|
| JSON 이 깨졌거나 객체가 아님 | 스킵 |
| `host` 가 비어 있음 | 스킵. 상관분석 키가 없으면 쓸모가 없다 |
| `type` 이 `process`/`network`/`file`/`script` 가 아님 | 스킵. 모르는 타입을 `process` 로 넘겨짚지 않는다 |
| `ts` 가 없거나 0 이하 | 스킵 |
| `ts` 가 `100000000000` 미만 | 스킵. 초 단위를 밀리초로 착각해 보낸 값이다 |
| `type` 이 `network` 인데 `destIp` 가 비어 있음 | 스킵 |

- 통과한 이벤트는 **값을 그대로 옮긴다.** basename 추출, 타입 추측, 시각 변환은 하지 않는다.
  그 일은 이제 에이전트가 한다. 경로 구분자가 플랫폼마다 다르니 그 플랫폼에서 도는 쪽이
  판단하는 게 맞다
- `ts` 와 `destPort` 는 숫자로 와도 문자열로 와도 받는다
- **검증 실패는 조용히 버린다.** 한 건이 이상하다고 컨슈머가 멈추면 그 뒤의 정상 이벤트까지 막힌다
- `tenantId` 는 손대지 않고 그대로 전달한다. 그 값은 api-service 가 node_key 를 풀어 심은 것이고
  ([`EventTagger`](../api-service/src/main/java/com/edrdog/apiservice/agent/EventTagger.java)),
  에이전트가 보낸 값이 있어도 서버가 덮어쓴다

발행할 때 **`host` 를 파티션 키로 쓴다.** 한 기기의 이벤트가 한 파티션에 모여야 detector 의
상관분석에서 순서가 보존된다.

## 엔드포인트 설치

에이전트 빌드·설정·설치와 알려진 한계는 [`../agent/README.md`](../agent/README.md) 에 있다.
서버와의 계약은 [`../docs/agent-protocol.md`](../docs/agent-protocol.md) 다.

## 실행

전제: [`../k8s/README.md`](../k8s/README.md) 로 Kafka 기동 (토픽 `events-raw`/`events`/`alerts` 생성됨).

```bash
./gradlew :collector-service:bootRun     # localhost:9092 소비/발행, 포트 8082
```

## 서버 준비: 에이전트 수집 HTTPS (api-service, dev)

에이전트는 서버 인증서를 고정하므로 수집 경로에는 HTTPS 가 필수다. dev 는 self-signed 키스토어를
만들어 에이전트 전용 커넥터(8443)를 연다. 프론트용 8084 와는 별도 포트다.

```bash
# 1) self-signed 키스토어 + 에이전트가 고정할 서버 cert(PEM) 생성
./scripts/gen-dev-keystore.sh ./dev-tls localhost

# 2) api-service 기동 (HTTPS 커넥터 켜기)
AGENT_TLS_ENABLED=true \
AGENT_TLS_KEYSTORE=./dev-tls/agent-keystore.p12 \
AGENT_TLS_KEYSTORE_PASSWORD=changeit \
./gradlew :api-service:bootRun

# 3) enroll secret 발급: 프론트 로그인 후 아래를 호출해 나온 값을 엔드포인트에 심는다.
#    POST /api/tenant/enroll-secret  → { "enrollSecret": "..." }
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
# collector 기동 상태에서. enroll secret 은 위 `서버 준비` 3)에서 발급.
SECRET=<발급받은 enroll secret>
KEY=$(curl -sk https://localhost:8443/api/agent/enroll -H 'Content-Type: application/json' \
  -d "{\"enroll_secret\":\"$SECRET\",\"host_identifier\":\"mac-001\",\"platform\":\"darwin\"}" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["node_key"])')

# 이벤트 1건 주입 → tenant 태깅 후 events-raw 발행
curl -sk https://localhost:8443/api/agent/events \
  -H 'Content-Type: application/json' -H "X-Node-Key: $KEY" \
  -d '{"events":[{"host":"mac-001","type":"process","ts":1785341400000,"process":"bash","parent":"zsh","cmdline":"bash -c whoami"}]}'
# 기대: {"accepted":1}

# events 에서 검증 통과분 확인
kubectl -n edrdog exec deploy/kafka -- /opt/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server localhost:9094 --topic events --from-beginning --max-messages 1
# 기대: {"host":"mac-001","type":"process","ts":1785341400000,"process":"bash","parent":"zsh","cmdline":"bash -c whoami","destIp":null,"destPort":0,"tenantId":"<tenant>"}
```

검증 규칙이 실제로 거르는지 보려면 `ts` 를 초 단위(`1785341400`)로 바꾸거나 `type` 을 `dns` 로
바꿔 같은 요청을 보낸다. `accepted` 는 그대로 1 이지만(수집 API 는 형태를 강제하지 않는다)
`events` 에는 아무것도 나오지 않아야 한다.

## 룰 검증 (Atomic Red Team)

검증 경로까지 확인되면 실제 악성행위를 재현해 detector 룰을 본다. (실제 호스트에서 수동 실행)

```bash
Invoke-AtomicTest T1059.001            # Windows PowerShell
# macOS 는 osascript/bash 계열 원자 테스트 사용
```

실행 후 `events-raw` → `events` → `alerts` 흐름과 detector 판정 로그를 확인한다.

## 한계 (알려진 것)

- **검증 실패가 조용하다.** 스킵한 이벤트를 세거나 남기지 않는다. 에이전트가 스키마를 어긋나게
  보내기 시작해도 `events` 건수가 줄어드는 것으로만 드러난다. 지금 규모에서는 카운터를 붙일 만한
  이득이 없다고 봤다
- **에이전트가 보낸 값의 내용은 검증하지 않는다.** `host` 가 비지 않았는지만 보고 그 기기가 정말
  그 이름인지는 따지지 않는다. 조직 격리는 `tenantId` 로 하고 그 값은 서버가 node_key 로 푼다
- **수집 API 는 이벤트 형태를 강제하지 않는다.** 스키마가 늘어도 서버를 다시 배포할 필요가 없게
  하려고 그렇게 두었다. 대신 형태가 틀린 이벤트는 여기까지 와서야 걸린다
- 엔드포인트 쪽 한계(macOS 네트워크 폴링, Windows 실기기 미검증 등)는
  [`../agent/README.md`](../agent/README.md) 의 `알려진 한계` 에 정리해 두었다
