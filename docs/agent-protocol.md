# 에이전트 프로토콜

자체 수집기(`agent/`)와 서버(`api-service`) 사이의 계약이다.

기존에는 osquery 의 TLS remote 규약(`enroll`/`config`/`log`)을 그대로 썼다. 자체 수집기로 옮기면서
그 규약을 버린다. osquery 는 자기 표준 포맷으로만 로그를 내기 때문에 `columns` 중첩과
`node_invalid` 같은 껍데기가 붙었는데, 이제 양쪽을 다 우리가 만드니 그럴 이유가 없다.

## 전송

| | |
|:---|:---|
| 포트 | 에이전트 전용 HTTPS 커넥터 (프론트용 HTTP 포트와 분리) |
| 인증 | `X-Node-Key` 헤더. `enroll` 만 예외 |
| 실패 | HTTP 상태 코드로 알린다. 200 본문에 실패를 담지 않는다 |
| 인코딩 | JSON, UTF-8 |

에이전트는 `401` 을 받으면 저장한 node_key 를 버리고 다시 등록한 뒤 한 번 재시도한다.
서버가 재시작해 키를 잃어도 사람이 손대지 않고 복구되어야 한다.

## 1. 등록

```
POST /api/agent/enroll
```

```json
{
  "enroll_secret": "조직마다 다른 비밀값",
  "host_identifier": "lab-mac",
  "platform": "darwin",
  "agent_version": "0.1.0"
}
```

`platform` 은 Go 의 `runtime.GOOS` 값 그대로 `darwin` 또는 `windows` 다.
osquery 는 여기에 비트마스크 숫자를 보내서 서버가 숫자와 이름을 모두 처리해야 했다. 그 분기는 없앤다.

**200**

```json
{ "node_key": "추측 불가 랜덤 토큰" }
```

**401** — enroll_secret 이 어느 조직과도 맞지 않음

```json
{ "error": "invalid_enroll_secret" }
```

## 2. 하트비트

```
POST /api/agent/heartbeat
X-Node-Key: ...
```

본문 없음. 서버는 이 호출로 마지막 접속 시각을 갱신한다(온라인 여부 관측용).

**200**

```json
{
  "config": {
    "sensors": { "process": true, "network": true, "file": true, "dns": true },
    "watch_paths": [
      "/Library/LaunchAgents",
      "/Library/LaunchDaemons"
    ],
    "flush_interval_seconds": 5
  },
  "commands": [
    { "id": "01J...", "type": "kill_process", "target": "/tmp/evil.sh" }
  ]
}
```

설정과 명령을 한 응답에 같이 내려준다. 대응 채널을 따로 열지 않는 이유는 엔드포인트가 방화벽
안쪽에 있어 서버가 먼저 접속할 수 없기 때문이다. 에이전트가 주기적으로 물어보는 쪽이 유일하게
설치 부담 없이 동작한다.

`watch_paths` 는 파일 감시 대상이다. 플랫폼별 기본값은 서버가 정해 내려준다.

`commands` 는 아직 처리되지 않은 명령만 담는다. 같은 명령을 두 번 받아도 안전해야 하므로
에이전트는 이미 실행한 `id` 를 기억하고 건너뛴다.

## 3. 이벤트 전송

```
POST /api/agent/events
X-Node-Key: ...
```

```json
{
  "events": [
    {
      "host": "lab-mac",
      "type": "process",
      "ts": 1785341400000,
      "process": "sh",
      "parent": "bash",
      "cmdline": "sh -c whoami",
      "destIp": null,
      "destPort": 0
    }
  ]
}
```

이벤트 한 건의 형식은 detector 가 판정 입력으로 쓰는 스키마와 같다. 중간 변환이 없다.

| 필드 | 의미 |
|:---|:---|
| `host` | 엔드포인트 식별자. 상관분석 키 |
| `type` | `process` / `network` / `file` / `script` / `dns` / `l7` |
| `ts` | 발생 시각, epoch millis |
| `process` | 프로세스명 또는 파일명. **전체 경로가 아니라 basename** |
| `parent` | 부모 프로세스명. process/script 만 |
| `cmdline` | 명령행. file/script 는 판정에 쓰는 전체 경로를 여기 담는다 |
| `destIp` | 목적지 IP. network 와 l7 |
| `destPort` | 목적지 포트. network 와 l7 |
| `domain` | DNS 질의 이름 또는 TLS SNI. dns 와 l7 |
| `detail` | 타입별 부가정보를 담은 JSON 문자열 |

`domain` 을 `detail` 안에 넣지 않고 따로 둔 이유는 검색 때문이다. 대시보드에서 도메인으로
찾을 수 있어야 하는데 JSON 안에 묻히면 조회가 어렵다.

`detail` 은 판정에 쓰지 않고 조사 화면에서 보여줄 값만 담는다. dns 는 질의 타입과 응답 IP 목록,
l7 은 인증서 발급자와 주체, 지문, TLS 버전 같은 것이다. 인증서 항목이 늘 때마다 컬럼을 늘리고
서비스 셋을 같이 배포하는 비용이 이득보다 커서 JSON 한 칸으로 묶었다.

**패킷 페이로드는 어떤 형태로도 보내지 않는다.** 통신 내용을 서버로 옮기는 것은 수집이 아니라
감청이다. 패킷은 엔드포인트 메모리에서 메타데이터만 뽑고 그 자리에서 버린다.

basename 추출은 에이전트가 한다. 서버가 하던 일을 옮긴 것이고, 경로 구분자가 플랫폼마다 다르니
그 플랫폼에서 도는 쪽이 판단하는 게 맞다.

`tenantId` 는 **에이전트가 보내지 않는다.** 서버가 node_key 로 풀어 심는다. 엔드포인트가 보낸 값을
믿으면 다른 조직의 태그를 붙일 수 있다.

**200**

```json
{ "accepted": 1 }
```

전송에 실패하면 에이전트는 그 배치를 버퍼 앞으로 되돌리고 다음 주기에 다시 보낸다.

## 4. 명령 결과 보고

```
POST /api/agent/command-result
X-Node-Key: ...
```

```json
{
  "command_id": "01J...",
  "status": "KILLED",
  "message": "pid 4242 종료"
}
```

**200** — 본문 없음

에이전트가 쓰는 상태는 셋뿐이다.

| 상태 | 뜻 |
|:---|:---|
| `KILLED` | 대상을 찾아 종료했다 |
| `NO_MATCH` | 그 이름/경로로 도는 프로세스가 없다 |
| `FAILED` | 찾았지만 종료하지 못했다 |

`TIMEOUT` / `COOLDOWN` / `DISABLED` 는 서버가 붙인다. 엔드포인트는 그 판단을 할 수 없다.

## 대응이 동기로 보이는 이유

대시보드에서 조치 버튼을 누르면 결과가 바로 나와야 한다. 그런데 에이전트는 방화벽 안쪽이라
서버가 먼저 부를 수 없고, 하트비트를 기다려야 한다.

그래서 서버가 대신 기다린다. `POST /api/responder/kill` 은 명령을 큐에 넣고 결과가 올 때까지
블로킹한다. 하트비트 주기가 짧으면 사람이 느끼는 지연은 몇 초다. 기다리다 상한을 넘기면
`TIMEOUT` 이다.

이 구조는 Fleet 을 쓸 때와 같다. Fleet 의 `scripts/run/sync` 도 fleetd 의 폴링을 서버가 대신
기다려 주는 동기 API 였다. 그래서 이 채널을 바꿔도 `KillController` 부터 알림 `CONFIRMED` 전환까지
그대로 둘 수 있다.

## 명령 종류

### kill_process

`target` 은 종료할 대상이다. detector 가 알림에 실어 보낸 값을 그대로 쓴다.
전체 경로가 있으면 경로, 없으면 프로세스명이다.

에이전트는 실행 중인 프로세스에서 대상을 찾아 종료한다. 경로가 오면 실행 파일 경로가 일치하는
프로세스를, 이름이 오면 파일명이 일치하는 프로세스를 찾는다.

자기 자신과 PID 1 은 절대 종료하지 않는다.
