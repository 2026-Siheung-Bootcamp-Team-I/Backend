# collector — osquery/Zeek 수집 정규화

osquery 엔드포인트는 **api-service 의 osquery TLS 수집 API**(`/api/osquery/enroll·config·log`)로 붙는다.
서버가 result-log 를 tenant 태깅해 `events-raw` 토픽으로 발행하면, collector 가 그 **원시 result-log** 를
소비해 detector 스키마(`Event`)로 정규화한 뒤 `events` 토픽으로 재발행한다.

```
osquery ──TLS(enroll/config/log)──▶ api-service ──▶ [events-raw] ──▶ collector ──▶ [events] ──▶ detector / archiver
 (엔드포인트)                        수집·tenant태깅     원시 로그       정규화        정규화된 이벤트
```

- **수집 쿼리(schedule)는 서버가 내려준다**: 엔드포인트에 로컬 config 파일을 두지 않는다.
  osquery 가 `--config_plugin=tls` 로 `/api/osquery/config` 를 받아오고, 그 스케줄은
  api-service 의 `OsqueryConfig.forPlatform()` 이 플랫폼별로 생성한다.
- collector 는 detector 오른쪽(정규화 이후)은 손대지 않는다. 껍데기를 벗기고 단위/필드를 맞추는 정규화 레이어다.

## 정규화 규칙 (`RawEventMapper`)

| Event 필드 | osquery 원시 | 처리 |
|---|---|---|
| `host` | 래핑 `hostIdentifier` (폴백 `hostname`) | 그대로 |
| `ts` | 래핑 `unixTime`(초) | ×1000 (밀리초) |
| `type` | 쿼리명 `name` | socket/network 포함 → `network`, 그 외 → `process` |
| `process` | `columns.path` | basename (`/`, `\` 모두 처리) |
| `parent` | `columns.parent` | 서버 config 가 `processes` 조인으로 **이름**을 채워 내려줌 |
| `cmdline` | `columns.cmdline` | 그대로 |
| `destIp` / `destPort` | `columns.remote_address` / `remote_port` | 그대로 / 정수 변환 |
| `tenantId` | 루트 `tenantId` | 수집 API 가 node_key→tenant 로 풀어 태깅한 값 |

- 차등 로그 top-level `action == "removed"`(프로세스 종료 등)는 스킵.
- `columns` 없음 / 깨진 JSON 은 예외 없이 스킵(유실보다 안전).

## 실행 (백엔드)

전제: `k8s/README.md` 로 Kafka 기동 (토픽 `events-raw`/`events`/`alerts` 생성됨).

```bash
./gradlew :collector-service:bootRun     # localhost:9092 소비/발행, 포트 8082
```

## 서버 준비 — osquery TLS 수집 API (api-service, dev)

osquery TLS logger 는 평문 HTTP 로 붙지 않으므로 수집 경로에는 HTTPS 가 필수다.
dev 는 self-signed 키스토어를 만들어 osquery 전용 HTTPS 커넥터(8443)를 연다.

```bash
# 1) self-signed 키스토어 + osquery 가 핀할 서버 cert(PEM) 생성
./scripts/gen-dev-keystore.sh ./dev-tls localhost

# 2) api-service 기동 (HTTPS 커넥터 켜기)
OSQUERY_TLS_ENABLED=true \
OSQUERY_TLS_KEYSTORE=./dev-tls/osquery-keystore.p12 \
OSQUERY_TLS_KEYSTORE_PASSWORD=changeit \
./gradlew :api-service:bootRun

# 3) enroll secret 발급: 프론트 로그인 후 아래를 호출해 나온 값을 엔드포인트에 심는다.
#    POST /api/tenant/enroll-secret  → { "enrollSecret": "..." }
```

엔드포인트는 `./dev-tls/osquery-server.pem` 을 `--tls_server_certs` 로 핀하고, 발급받은 enroll secret 을
`enroll_secret_path` 파일에 저장한다.

## 실행 (엔드포인트 = osquery)

> ⚠️ 이 부분은 실제 머신에서 사람이 권한을 승인해야 하며 자동화 불가.
> Issue #16/#41 의 "macOS 권한 승인 / Windows 배포가 최대 고비"가 여기다.

공용 파일: OS별 플래그 [`osquery/osquery.mac.flags`](osquery/osquery.mac.flags) /
[`osquery/osquery.win.flags`](osquery/osquery.win.flags).
`--tls_hostname` 은 **엔드포인트에서 도달 가능한 api-service HTTPS 주소**로 맞출 것
(같은 머신 데모면 `localhost:8443`, 원격이면 실주소).

### macOS

`es_process_events`(EndpointSecurity)는 **Full Disk Access(FDA)** 가 없으면 에러 없이 조용히 빈 결과가 된다.

1. osquery 설치: `brew install --cask osquery`
2. enroll secret / 서버 cert 를 배치: `/etc/osquery/enroll.secret`, `/etc/osquery/osquery-server.pem`
3. **FDA 부여**: 시스템 설정 → 개인정보 보호 및 보안 → 전체 디스크 접근 → osqueryd 바이너리 추가.
   - `.app` 번들이 아니라 그 안의 유닉스 바이너리를 지정
     (`/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd`, `Cmd+Shift+G`).
4. **launchd 데몬으로 실행**(포그라운드/대화형은 TCC 가 터미널 앱에 귀속돼 안 됨):
   ```bash
   sudo osqueryd --flagfile /path/to/osquery/osquery.mac.flags
   # 또는 osqueryctl 로 데몬 등록 후 sudo osqueryctl start
   ```
5. **재부팅**: TCC(FDA) 권한은 살아있는 세션에 즉시 반영되지 않는다. 재부팅 후 exec 이벤트 수집 확인.
6. 이벤트가 안 잡히면 FDA/EndpointSecurity 권한부터 의심.

### Windows

`process_etw_events`(ETW)로 프로세스 생성을 감시. **관리자 권한**으로 실행.
network 이벤트는 core osquery 에 실시간 소켓 테이블이 없어 **Zeek 가 담당**한다.

```powershell
osqueryd.exe --flagfile C:\ProgramData\osquery\osquery.win.flags
```

`process_etw_events.type` 리터럴은 버전마다 다를 수 있다. 안 잡히면
`osqueryi.exe` 에서 `SELECT DISTINCT type FROM process_etw_events;` 로 확인 후 서버 `OsqueryConfig` 의 `WHERE` 수정.

## 수집 API 배선 검증 (FDA 없이)

osquery/FDA 없이 서버 수집 API 전 구간(enroll→config→log→events-raw→collector→events)만 검증하려면
`OsqueryIngestIntegrationTest` 를 쓰거나, HTTPS 커넥터에 직접 원시 로그를 넣어 본다.

```bash
# collector 기동 상태에서. enroll secret 은 위 "서버 준비" 3)에서 발급.
SECRET=<발급받은 enroll secret>
KEY=$(curl -sk https://localhost:8443/api/osquery/enroll -H 'Content-Type: application/json' \
  -d "{\"enroll_secret\":\"$SECRET\",\"host_identifier\":\"mac-001\",\"platform_type\":\"darwin\"}" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["node_key"])')

# 원시 result-log 1건 주입 → tenant 태깅 후 events-raw 발행
curl -sk https://localhost:8443/api/osquery/log -H 'Content-Type: application/json' \
  -d "{\"node_key\":\"$KEY\",\"log_type\":\"result\",\"data\":[{\"name\":\"process_events\",\"hostIdentifier\":\"mac-001\",\"unixTime\":\"1700000000\",\"action\":\"added\",\"columns\":{\"path\":\"/bin/bash\",\"cmdline\":\"bash -c whoami\",\"parent\":\"zsh\"}}]}"

# events 에서 정규화된 결과 확인
kubectl -n edrdog exec deploy/kafka -- /opt/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server localhost:9094 --topic events --from-beginning --max-messages 1
# 기대: {"host":"mac-001","type":"process","ts":1700000000000,"process":"bash","parent":"zsh","cmdline":"bash -c whoami","destIp":null,"destPort":0,"tenantId":"<tenant>"}
```

## 룰 검증 (Atomic Red Team)

정규화까지 확인되면 실제 악성행위를 재현해 detector 룰을 검증한다. (실제 호스트에서 수동 실행)

```bash
Invoke-AtomicTest T1059.001            # Windows PowerShell
# macOS 는 osascript/bash 계열 원자 테스트 사용
```

실행 후 `events-raw` → `events` → `alerts` 흐름과 detector 판정 로그를 확인한다.

## 한계 (알려진 것)

- **macOS es_process_events = FDA + 재부팅 필수**: macOS 26 + osquery 5.23.1 에서 EndpointSecurity 는
  osqueryd 에 FDA 가 있어야만 동작한다(없으면 `EndpointSecurity client lacks user TCC permissions` 로 조용히 거부).
  대화형/포그라운드는 TCC 가 터미널 앱에 귀속돼 안 되니 반드시 launchd 데몬으로 실행. 무인 배포는 MDM PPPC 프로파일로 FDA 사전 승인.
- **macOS 네트워크(socket_events)**: OpenBSM 기반이라 신형 macOS 에서 비활성/deprecated 가능. 네트워크는 Zeek 담당.
- **부모 프로세스명**: osquery 에 부모 이름 컬럼이 없어 서버 config 가 `ppid`→`processes` 조인으로 채운다.
  단명(短命) 프로세스는 조인 시점에 부모가 이미 종료돼 이름이 비는 경우가 있다(osquery #8044).
  더 정확히 하려면 collector 에 프로세스 트리 캐시(생성 이벤트로 `pid→name` 유지)를 추가해야 하나, 현재 규모에선 과설계라 미도입.
- **Windows 네트워크 / DNS**: core osquery 미지원 → Zeek 로 커버.
- **platform 판정**: 서버는 enroll 의 `platform_type` 문자열에 `windows` 가 들어가면 Windows, 그 외는 macOS 스케줄로 폴백한다.
