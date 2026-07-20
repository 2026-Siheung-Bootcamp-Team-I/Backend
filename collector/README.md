# collector — osquery/Zeek 수집 정규화

osquery/Zeek 가 kafka_producer 로 보낸 **원시 result-log**(`events-raw` 토픽)를 소비해
detector 스키마(`Event`)로 정규화한 뒤 `events` 토픽으로 재발행한다.

```
osquery/Zeek ──kafka_producer──▶ [events-raw] ──▶ collector ──▶ [events] ──▶ detector / archiver
                (엔드포인트)         원시 로그       정규화        정규화된 이벤트
```

osquery 는 소비자 스키마에 맞추지 않고 자기 표준 포맷(껍데기로 감싼 차등 로그)으로만 로그를 낸다.
그 껍데기를 벗기고 단위/필드를 맞추는 정규화 레이어가 collector 다. detector 오른쪽은 손대지 않는다.

## 정규화 규칙 (`RawEventMapper`)

| Event 필드 | osquery 원시 | 처리 |
|---|---|---|
| `host` | 래핑 `hostIdentifier` (폴백 `hostname`) | 그대로 |
| `ts` | 래핑 `unixTime`(초) | ×1000 (밀리초) |
| `type` | 쿼리명 `name` | socket/network 포함 → `network`, 그 외 → `process` |
| `process` | `columns.path` | basename (`/`, `\` 모두 처리) |
| `parent` | `columns.parent` | osquery.conf 에서 `processes` 조인으로 이름을 넣어 둠 |
| `cmdline` | `columns.cmdline` | 그대로 |
| `destIp` / `destPort` | `columns.remote_address` / `remote_port` | 그대로 / 정수 변환 |

- 차등 로그 top-level `action == "removed"`(프로세스 종료 등)는 스킵.
- `columns` 없음 / 깨진 JSON 은 예외 없이 스킵(유실보다 안전).

## 실행 (백엔드)

전제: `k8s/README.md` 로 Kafka 기동 (토픽 `events-raw`/`events`/`alerts` 생성됨).

```bash
./gradlew :collector:bootRun     # localhost:9092 소비/발행, 포트 8082
```

빠른 확인 — 원시 로그 1건을 손으로 넣어 정규화 결과를 본다:

```bash
# events-raw 에 osquery 원시 result-log 1건 주입
kubectl -n edrdog exec -i deploy/kafka -- \
  /opt/kafka/bin/kafka-console-producer.sh --bootstrap-server localhost:9094 --topic events-raw <<'EOF'
{"name":"process_events","hostIdentifier":"mac-001","unixTime":"1700000000","action":"added","columns":{"path":"/bin/bash","cmdline":"bash -c whoami","parent":"zsh"}}
EOF

# events 에서 정규화된 결과 확인
kubectl -n edrdog exec deploy/kafka -- \
  /opt/kafka/bin/kafka-console-consumer.sh --bootstrap-server localhost:9094 --topic events --from-beginning --max-messages 1
# 기대: {"host":"mac-001","type":"process","ts":1700000000000,"process":"bash","parent":"zsh","cmdline":"bash -c whoami","destIp":null,"destPort":0}
```

## 실행 (엔드포인트 = osquery)

> ⚠️ 이 부분은 실제 머신에서 사람이 권한을 승인해야 하며 자동화 불가.
> Issue #16 의 "macOS audit + 전체디스크접근이 최대 고비"가 여기다.

공용 파일: [`osquery/osquery.flags`](osquery/osquery.flags) (Kafka 로거 설정),
OS별 설정: [`osquery.macos.conf`](osquery/osquery.macos.conf) / [`osquery.windows.conf`](osquery/osquery.windows.conf).

`osquery.flags` 의 `--logger_kafka_brokers` 는 **엔드포인트에서 도달 가능한 브로커 주소**로 맞출 것
(같은 머신 데모면 `localhost:9092`, 원격이면 브로커 실주소).

### macOS

`es_process_events`(EndpointSecurity)는 **Full Disk Access(FDA)** 가 없으면 에러 없이 조용히 빈 결과가 된다.

1. osquery 설치: `brew install --cask osquery`
2. **FDA 부여**: 시스템 설정 → 개인정보 보호 및 보안 → 전체 디스크 접근 → `osqueryd`(`/usr/local/bin/osqueryd`) 추가.
   - Terminal 에서 띄우면 Terminal.app 에도 FDA 필요. launchd 로 띄우면 osqueryd 바이너리에.
3. 실행:
   ```bash
   sudo osqueryd \
     --flagfile /path/to/collector/osquery/osquery.flags \
     --config_path /path/to/collector/osquery/osquery.macos.conf \
     --disable_endpointsecurity=false
   ```
4. 이벤트가 안 잡히면 FDA/EndpointSecurity 권한부터 의심.

### Windows

`process_etw_events`(ETW)로 프로세스 생성을 감시. **관리자 권한**으로 실행.
network 이벤트는 core osquery 에 실시간 소켓 테이블이 없어 **Zeek 가 담당**한다.

```powershell
osqueryd.exe ^
  --flagfile C:\path\to\collector\osquery\osquery.flags ^
  --config_path C:\path\to\collector\osquery\osquery.windows.conf
```

`process_etw_events.type` 리터럴은 버전마다 다를 수 있다. 안 잡히면:
`osqueryi.exe` 에서 `SELECT DISTINCT type FROM process_etw_events;` 로 확인 후 conf 의 `WHERE` 수정.

## 룰 검증 (Atomic Red Team)

정규화까지 확인되면 실제 악성행위를 재현해 detector 룰을 검증한다. (실제 호스트에서 수동 실행)

```bash
# 예: T1059 - 스크립트 인터프리터 실행 (endpoint 에서)
Invoke-AtomicTest T1059.001            # Windows PowerShell
# macOS 는 osascript/bash 계열 원자 테스트 사용
```

실행 후 `events-raw` → `events` → `alerts` 흐름과 detector 판정 로그를 확인한다.

## 로컬 배관 검증 (FDA 없이)

es_process_events(FDA 필요)와 무관하게 osquery→Kafka→collector→events 전 구간을 검증하는 방법.
권한이 필요 없는 `processes`(스냅샷) 차등 쿼리를 쓴다. 설정: [`smoketest.flags`](osquery/smoketest.flags) / [`smoketest.conf`](osquery/smoketest.conf).

```bash
# 1) collector 기동:  ./gradlew :collector:bootRun
# 2) osquery 로 실제 프로세스를 events-raw 로 전송 (실터미널, sudo)
sudo /opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd \
  --flagfile   collector/osquery/smoketest.flags \
  --config_path collector/osquery/smoketest.conf \
  --allow_unsafe
# 3) events 에서 정규화된 실제 프로세스 이벤트 확인
kubectl -n edrdog exec deploy/kafka -- /opt/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server localhost:9094 --topic events --max-messages 5
```

이 경로는 실제 macOS 에서 검증 완료(프로세스 수백 건이 events 로 정규화됨).

## 한계 (알려진 것)

- **macOS es_process_events = FDA + 재부팅 필수**: macOS 26 + osquery 5.23.1 에서
  EndpointSecurity 는 osqueryd 에 전체 디스크 접근(FDA)이 있어야만 동작한다(없으면
  `EndpointSecurity client lacks user TCC permissions` 로 조용히 거부). 검증된 동작 순서:
  1) osqueryd 바이너리(`/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd`)를 FDA 에 추가·활성화
     (`.app` 번들이 아니라 그 안의 유닉스 바이너리를 `Cmd+Shift+G` 로 지정),
  2) 데몬 설치·기동(`sudo osqueryctl start`, plist 가 `/Library/LaunchDaemons` 에 복사되는지 확인),
  3) **재부팅**(TCC 권한이 살아있는 세션에는 반영 안 됨, 재부팅 후 적용). → 재부팅 뒤 실제 exec 이벤트 수집 확인 완료.
  대화형 `sudo osqueryi`/포그라운드는 TCC 가 터미널 앱에 귀속돼 안 되니, 반드시 launchd 데몬으로 실행할 것.
  무인 배포는 MDM PPPC 프로파일로 FDA 를 사전 승인. Issue #16 이 예고한 "최대 고비" 지점.
- **macOS 네트워크(socket_events)**: OpenBSM 기반이라 신형 macOS 에서 비활성/deprecated. 네트워크는 Zeek 담당.
- **부모 프로세스명**: osquery 에 부모 이름 컬럼이 없어 `ppid`→`processes` 조인으로 채운다.
  단명(短命) 프로세스는 조인 시점에 부모가 이미 종료돼 이름이 비는 경우가 있다(osquery #8044).
  더 정확히 하려면 collector 에 프로세스 트리 캐시(생성 이벤트로 `pid→name` 유지)를 추가해야 하나,
  현재 규모에선 과설계라 미도입.
- **Windows 네트워크**: core osquery 미지원 → Zeek 로 커버.
