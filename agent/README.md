# EDRdog 에이전트

> 엔드포인트에서 프로세스·네트워크·파일 행위를 관찰해 서버로 보내고, 서버가 내린 조치를 실행하는 자체 수집기

Go 로 쓴 단일 실행 파일이다. 대상은 **macOS 와 Windows** 뿐이다.
서버와의 계약은 [`../docs/agent-protocol.md`](../docs/agent-protocol.md) 에 있다.

## 검증 상태

무엇이 확인됐고 무엇이 확인 안 됐는지부터 적는다. 이 구분을 흐리면 문서가 쓸모없어진다.

**확인된 것**

| | |
|:---|:---|
| Go 테스트 | 전 패키지 통과. race 검출기 포함 |
| 빌드 | macOS, Windows, Linux 세 플랫폼 통과. `go vet` 통과 |
| 서버까지 왕복 | 실제 바이너리로 확인. 등록 → 하트비트로 설정과 명령 수신 → 이벤트 네 종류 전송 → 조치 명령 실행 후 결과 보고 |
| 프로세스 종료 | 표적 프로세스가 실제로 종료되는 것까지 확인 |
| 서버 쪽 | Java 테스트 391개 통과 |

**확인 안 된 것 (전부 Windows 다)**

- **Windows ETW 센서를 실제 Windows 기기에서 한 번도 돌려보지 않았다.** 크로스 빌드와 순수 로직
  단위 테스트까지가 전부다
- **상수가 틀려도 빌드는 통과하고 조용히 0건이 된다. 이게 가장 위험하다.** 프로바이더 GUID,
  keyword 비트, 이벤트 ID 는 컴파일러가 검사해 주지 않는다. 값 하나가 어긋나면 오류 없이
  이벤트만 안 온다
- Windows 서비스 등록과 `-service` 경로도 실기기 미검증이다
- 설치 스크립트 두 개 다 실기기 미검증이다

확인 절차는 아래 [Windows 실기기 검증 절차](#windows-실기기-검증-절차) 에 우선순위 순으로 정리해 두었다.

## 어떤 이벤트를 어떻게 얻나

플랫폼마다 커널이 사건을 알려주는 방식이 다르다. 그 차이는 에이전트 안에서 흡수하고, 서버에는
detector 가 그대로 판정에 쓰는 평평한 JSON 한 종류로 보낸다.

| | 프로세스 | 네트워크 | 파일 |
|:---|:---|:---|:---|
| **Windows** | ETW `Microsoft-Windows-Kernel-Process` ProcessStart(1) | ETW `Microsoft-Windows-Kernel-Network` TCP 연결 시도(12/28) | ETW `Microsoft-Windows-Kernel-File` CreateNewFile(30). **새로 생긴 파일만** |
| **macOS** | `eslogger` 의 `exec` | libproc 소켓 스냅샷 (**폴링**) | `eslogger` 의 `create`/`rename`/`unlink` |

**파일 이벤트의 범위가 두 플랫폼에서 다르다.** Windows 는 새로 생긴 파일만 잡고, macOS 는 생성에
더해 이름 변경과 삭제까지 받는다. 이유는 아래 각 플랫폼 절에 적었다.

이벤트 종류는 `process` / `network` / `file` / `script` 네 가지다. 실행된 파일이 셸이나 스크립트
인터프리터면 `process` 가 아니라 `script` 로 낸다. detector 가 `script` 에만 T1059 룰을 걸기 때문이다.

### Windows: ETW 세션 하나로 셋 다 받는다

세 프로바이더를 `EDRdog-Agent` 라는 실시간 세션 하나에 붙인다. 이벤트 ID 와 keyword 를 지정해
커널 단계에서 걸러 내므로 우리 콜백까지 올라오는 양 자체가 줄어든다. 둘은 **AND 로 걸린다.**
이벤트 ID 를 켜 두어도 그에 대응하는 keyword 비트가 빠져 있으면 그 ID 는 조용히 0건이 된다.

`NT Kernel Logger` 는 쓰지 않는다. 시스템 전체에 하나뿐이라 다른 도구와 부딪힌다.

프로바이더는 GUID 를 손으로 적지 않고 이름으로 풀어 쓴다. 켤 때 쓰는 이름과 이벤트를 가를 때 쓰는
GUID 가 따로 놀면, 어긋나도 오류가 나지 않고 조용히 0건이 되기 때문이다.

**Kernel-Process 의 ProcessStart 에는 커맨드라인 필드가 아예 없다.** 매니페스트에 정의된 것이
`ProcessID`, `ParentProcessID`, `SessionID`, `ImageName` 까지다. 게다가 그 `ImageName` 도 전체
경로가 아니라 파일명만 오는 경우가 실기기에서 관측된 적이 있다. 그래서 에이전트는 이벤트를 받은
직후 그 PID 를 직접 열어 두 값을 보강한다.

| 채우는 값 | 쓰는 것 |
|:---|:---|
| 전체 이미지 경로 | `OpenProcess` + `QueryFullProcessImageNameW` |
| 커맨드라인 | `OpenProcess` + `NtQueryInformationProcess(ProcessCommandLineInformation)` |

여는 권한은 `PROCESS_QUERY_LIMITED_INFORMATION` 이면 충분하다. 짧게 살다 죽는 프로세스는 그 사이
이미 끝나서 실패할 수 있는데, 그때는 보강하지 않고 넘어간다. 그러면 이렇게 물러난다.

| 보강 결과 | `process` | `cmdline` |
|:---|:---|:---|
| 둘 다 성공 | 전체 경로의 파일명 | 읽어 온 명령행 (argv0 은 전체 경로로 바꿔 넣는다) |
| 경로만 성공 | 전체 경로의 파일명 | 전체 경로 |
| 둘 다 실패 | `ImageName` (파일명뿐) | 비워 둔다 |

마지막 줄에서 `cmdline` 에 파일명만 넣지 않는 것은 의도한 것이다. 판정에 쓸 값이 아니면서
responder 의 조치 대상만 이름으로 흐려 놓는다.

부모도 마찬가지다. ETW 는 부모를 PID 로만 주는데 서버 스키마의 `parent` 는 이름이라, 같은 방법으로
풀어 파일명만 남긴다.

**ProcessStop(2)도 같이 구독하지만 이벤트로 내보내지는 않는다.** 서버 스키마에 종료 타입이 없다.
그런데도 받는 이유는 진단이다. 이 저장소에는 세션과 프로바이더가 멀쩡한데 ProcessStop 만 올라오고
ProcessStart 는 한 건도 오지 않은 실기기 이력이 있다(커밋 `22a5983`). 둘을 같이 세어 두면
`Start 0건 / Stop 다수` 라는 모양이 로그에 그대로 드러나서, 프로바이더가 안 붙은 것인지 그 현상이
재현된 것인지 바로 가릴 수 있다.

**파일은 새로 생긴 것만 받는다.** `CreateNewFile(30)` 하나이고 keyword 는 `CREATE_NEW_FILE(0x1000)`
단독이다. 자동실행 경로에 파일이 놓이는 것을 잡는 게 목적이라(detector R4) 그 이상은 필요 없다.
Read(15)나 Write(16)까지 켜면 평범한 기기에서 초당 수천 건이 올라와 다른 이벤트를 전부 밀어낸다.

삭제(`DeletePath` 26)와 이름 변경(`RenamePath` 27)은 **일부러 뺐다.** 이 둘은 경로를 `FileName` 이
아니라 `FilePath` 에 싣는데 `MapFile` 은 `FileName` 만 읽는다. 켜 두면 이벤트가 올라와도 전부 조용히
버려진다. 켜 놓고 못 읽는 상태가 되느니 안 켜는 편이 낫다고 봤다. R4 에 필요한 것은 파일이 새로
생기는 것뿐이라 기능상 빠지는 것은 없다.

**나중에 삭제와 이름 변경까지 보려면 `MapFile` 이 `FilePath` 도 읽게 고친 뒤에 켜야 한다.** 프로바이더
설정만 되돌리면 이벤트는 오지만 전부 버려진다.

### macOS: eslogger 를 자식 프로세스로 띄운다

EndpointSecurity API 를 직접 부르려면 애플의 entitlement 심사를 통과해야 한다. `/usr/bin/eslogger`
는 그 권한을 이미 가진 애플 서명 바이너리라, 심사 없이 같은 이벤트를 받을 수 있다. 에이전트는
`eslogger --format json exec create rename unlink` 를 띄워 stdout 을 줄 단위로 읽는다.

네트워크만 다르다. **EndpointSecurity API 에는 소켓 연결 이벤트가 없다.** 그래서 `libproc` 로
프로세스별 열린 TCP 소켓을 주기마다 훑고, 직전 스냅샷에 없던 것만 새 연결로 본다. 첫 스냅샷은
기준선으로만 쓰고 이벤트를 내지 않는다. 에이전트가 막 떴을 때 이미 열려 있던 연결 수백 개를
전부 쏟는 것은 관측이 아니기 때문이다.

파일 이벤트는 서버가 내려준 감시 경로 아래의 것만 통과시킨다. 평범한 맥에서 create/rename/unlink
는 초당 수백 건이 나오고, 그걸 다 올리면 버퍼가 파일 이벤트로 가득 차 정작 중요한 이벤트가
밀려난다.

### 감시 경로의 사용자 자리는 에이전트가 채운다

파일 이벤트를 거를 감시 경로는 서버가 하트비트로 내려준다. 자동실행 경로가 늘어날 때 이미 배포된
엔드포인트를 다시 설치하지 않고 서버만 고쳐서 바꾸기 위해서다.

그런데 자동실행 경로에는 **사용자별 경로**가 섞여 있고, 서버는 그 기기에 어떤 계정이 있는지 모른다.
그래서 서버는 계정 자리를 표시만 해서 내려주고, 그 자리를 채우는 것은 그 기기에서 도는 에이전트가
한다. 사정은 같고 해결 방식만 플랫폼에 맞게 다르다.

| | 서버가 내려주는 것 | 에이전트가 하는 일 |
|:---|:---|:---|
| **macOS** | `~/Library/LaunchAgents` | `~` 를 실제 홈 디렉터리로 편다 (`ExpandWatchPaths`) |
| **Windows** | `C:\Users\*\AppData\Roaming\...\Startup` | `*` 를 경로 한 단계와 맞춘다 (`matchesWatchPath`) |

방식이 갈리는 이유는 커널이 주는 경로의 모양이 다르기 때문이다. macOS 는 절대 경로 하나로 오니
미리 펴 두면 되지만, Windows 는 `\Device\HarddiskVolume3\Users\...` 같은 장치 경로로 와서 미리
펴 둘 기준이 없다. 그래서 비교하는 시점에 단계별로 맞춘다. 장치 경로로 들어와도 걸린다.

**`*` 는 한 단계만 대신한다.** 여러 단계를 건너뛰게 하면 감시 범위가 의도보다 넓어진다.
`C:\Users\*\Startup` 은 `C:\Users\a\Startup` 에 걸리고 `C:\Users\a\b\Startup` 에는 걸리지 않는다.

## 빌드

Go 1.26.1 이상이 필요하다(`go.mod` 기준).

```bash
cd agent

go build ./cmd/edrdog-agent                                    # 지금 플랫폼용
GOOS=windows GOARCH=amd64 go build -o edrdog-agent.exe ./cmd/edrdog-agent
```

macOS 빌드는 `libproc` 를 쓰느라 cgo 가 켜져 있어야 한다(기본값). 그래서 **macOS 바이너리는
macOS 에서만 만들 수 있다.** Windows 바이너리는 순수 Go 라 어디서든 크로스 빌드된다.

판번호는 `-ldflags` 로 덮어쓴다. 이 값이 enroll 의 `agent_version` 으로 올라간다.

```bash
go build -ldflags "-X main.version=0.2.0" ./cmd/edrdog-agent
```

## 설정 파일

JSON 파일 하나다. 필드는 [`internal/config/config.go`](internal/config/config.go) 에 정의되어 있다.

```json
{
  "base_url": "https://edr.example.com:30443",
  "enroll_secret": "대시보드에서 발급받은 값",
  "host_identifier": "lab-mac",
  "ca_cert_path": "/etc/edrdog/server.pem",
  "flush_interval_seconds": 5,
  "buffer_size": 10000,
  "batch_size": 500
}
```

| 필드 | 필수 | 기본값 | 뜻 |
|:---|:---:|:---|:---|
| `base_url` | O | | 수집 서버 주소. 끝의 `/` 는 떼고 쓴다 |
| `enroll_secret` | O | | 조직마다 다른 등록용 비밀값 |
| `host_identifier` | | 호스트 이름 | 서버에서 이 기기를 가리키는 이름. 상관분석 키다 |
| `ca_cert_path` | | 없음 | **서버 인증서 고정.** 이 PEM 으로 서명된 서버만 신뢰한다. 비우면 시스템 신뢰 저장소를 쓴다 |
| `flush_interval_seconds` | | `5` | 이벤트 배치 전송 주기. **서버가 안 줄 때의 기본값이다.** 아래 참고. HTTP 타임아웃은 언제나 이 값을 쓴다 |
| `buffer_size` | | `10000` | 전송 대기 버퍼 상한. 넘치면 오래된 것부터 버린다 |
| `batch_size` | | `500` | 한 번에 보낼 이벤트 수 |

`enroll_secret` 이 들어 있으므로 파일 권한을 조여야 한다. 설치 스크립트는 macOS 에서 `0600`,
Windows 에서 SYSTEM 과 Administrators 만 남기는 ACL 을 건다.

`ca_cert_path` 를 지정하면 시스템 신뢰 저장소를 **같이 쓰지 않는다.** 같이 쓰면 고정이 아니게 되기
때문이다. 그래서 사설 CA 로 만든 self-signed 인증서도 그대로 쓸 수 있다.

**전송 주기는 서버가 정한다.** 하트비트 응답의 `flush_interval_seconds` 를 쓰고, 서버가 값을 주지
않으면(0 이하) 위 설정 파일 값으로 물러난다. 켤 센서(`sensors`)와 감시 경로(`watch_paths`)도
마찬가지로 서버가 정한다. 엔드포인트를 다시 설치하지 않고 서버만 고쳐서 바꾸기 위해서다.

## 실행

설정 파일만 주면 그 플랫폼의 센서가 뜬다.

```bash
./edrdog-agent -config /etc/edrdog/config.json
```

순서는 이렇다. 등록으로 node_key 를 받고, 첫 하트비트로 수집 설정(`sensors`, `watch_paths`)을
받은 다음, 그 설정에 맞는 센서를 구성해 **수집 루프와 명령 루프를 동시에** 돌린다. 둘을 따로 돌리는
이유는 서로를 기다리면 안 되기 때문이다. 조치 채널이 막혀도 수집은 계속돼야 하고, 서버가 이벤트를
안 받아도 조치는 나가야 한다.

**켤 센서가 하나도 없으면 기동을 거부한다.** 서버가 전부 껐거나 지원하지 않는 플랫폼일 때다.
조용히 0건으로 도는 상태가 이 프로젝트에서 가장 찾기 어려운 고장이었어서, 뜨지 않는 편을 골랐다.

| 플랫폼 | 뜨는 센서 |
|:---|:---|
| macOS | `eslogger` (process 또는 file 이 켜져 있으면), `netsnap` (network 가 켜져 있으면) |
| Windows | `etw` 하나. 세 종류를 세션 하나로 받는다 |
| 그 외 | 없음. 기동을 거부한다 |

## 설치

두 스크립트 모두 서버에서 인증서를 직접 받아 저장한다. 관리자가 PEM 파일을 따로 전달할 필요가 없다.
여러 번 실행해도 안전하다.

### macOS

```bash
cd agent
go build -o packaging/edrdog-agent ./cmd/edrdog-agent
sudo ./packaging/install-macos.sh --server edr.example.com:30443 --enroll-secret <발급받은 값>
```

바이너리를 `/usr/local/bin/edrdog-agent` 에 놓고, 설정을 `/etc/edrdog/config.json` 에 쓰고,
`/Library/LaunchDaemons/com.edrdog.agent.plist` 로 등록해 부팅 시 자동 기동시킨다.

**스크립트가 끝나도 아직 이벤트는 오지 않는다.** 전체 디스크 접근 권한을 사람이 직접 켜야 한다.

```
시스템 설정 > 개인정보 보호 및 보안 > 전체 디스크 접근
  → /usr/local/bin/edrdog-agent 추가하고 켜기

sudo launchctl kickstart -k system/com.edrdog.agent
```

```bash
sudo launchctl print system/com.edrdog.agent   # 상태
tail -f /var/log/edrdog/agent.log              # 로그
```

### Windows

> 이 절차는 **실제 Windows 기기에서 검증되지 않았다.** 아래 `Windows 실기기 검증 절차` 를 같이 봐라.

관리자 권한 PowerShell 에서 실행한다.

```powershell
.\install-windows.ps1 -Server edr.example.com:30443 -EnrollSecret <발급받은 값>
```

`C:\Program Files\EDRdog\edrdog-agent.exe` 에 놓고 설정을 `C:\ProgramData\EDRdog\config.json` 에
쓴 뒤 `edrdog-agent` 라는 Windows 서비스로 등록한다. LocalSystem 으로 돌기 때문에 ETW 세션을 열
권한이 이미 있고, macOS 와 달리 사람이 승인할 단계가 없다.

```powershell
Get-Service edrdog-agent
```

서비스로 등록될 때 바이너리에 `-service` 플래그가 붙는다. 이 플래그는 서비스 제어 관리자와
대화하는 모드로, 직접 실행할 때는 쓰지 않는다.

## `-selftest` 로 서버까지의 경로 확인

커널을 전혀 건드리지 않고 네 가지 타입의 가짜 이벤트를 한 벌씩 만들어 보낸다. 권한 문제와 수집
문제를 분리하는 용도다. 이게 대시보드까지 올라오면 등록·인증서 고정·전송·정규화·판정 경로가 전부
살아 있다는 뜻이고, 남은 문제는 센서 권한뿐이다.

```bash
./edrdog-agent -config ./config.json -selftest
./edrdog-agent -config ./config.json -selftest -selftest-interval 5s
```

보내는 것은 process 1건, script 1건, network 1건(`203.0.113.1:443`), file 1건이다.
`203.0.113.1` 은 문서용으로 예약된 대역(RFC 5737)이라 실제 통신은 일어나지 않는다.

기대 출력:

```
level=INFO msg="등록 완료" host=lab-mac platform=darwin version=0.1.0
level=INFO msg="수집 시작" sensors=[selftest] flush=5s
```

`등록 실패` 로 멈추면 `base_url`, `enroll_secret`, 인증서 SAN 중 하나가 틀린 것이다.

## 테스트

```bash
cd agent
go test ./...
go test -race ./...
go vet ./...
```

Windows 전용 코드까지 컴파일이 깨지지 않는지 보려면 크로스 빌드를 같이 돌린다.

```bash
GOOS=windows GOARCH=amd64 go build ./...
```

판정에 관여하는 로직은 플랫폼 코드에서 일부러 빼 두었다. `etw_map.go`, `netsnap.go`,
`eslogger_map.go`, `command/match.go` 에는 빌드 태그가 없어서 **개발 기기가 macOS 여도 Windows
매핑 로직이 그대로 테스트된다.** 빌드 태그가 붙은 파일(`etw_windows.go`)은 세션을 열고 속성을
꺼내 넘기는 배선만 한다.

## 알려진 한계

### Windows 쪽은 실기기에서 검증되지 않았다

크로스 컴파일과 순수 로직 단위 테스트까지만 통과했다. 확인하지 못한 것은 센서만이 아니다.

| | 확인 못 한 것 |
|:---|:---|
| ETW 센서 | 세션이 실제로 열리는지, 구독한 이벤트가 실제로 오는지, 속성 이름과 값 형식이 매니페스트와 같은지 |
| 서비스 | `-service` 경로와 SCM 등록, 부팅 후 자동 기동 |
| 설치 스크립트 | `install-windows.ps1`, `install-macos.sh` 둘 다 실기기 미검증 |

**상수가 틀려도 빌드는 통과하고 조용히 0건이 된다.** 프로바이더 GUID, keyword 비트, 이벤트 ID 는
컴파일러가 검사해 주지 않는 값이다. 이게 가장 위험한 실패 모드라 검증 절차를 그 순서로 짰다.
확인 항목은 아래 [Windows 실기기 검증 절차](#windows-실기기-검증-절차) 에 있다.

### macOS 네트워크는 이 에이전트에서 유일하게 폴링이다

EndpointSecurity API 에 소켓 연결 이벤트가 없어서 그렇다. 진짜 연결 이벤트를 구독하려면
NetworkExtension entitlement 가 필요한데 그건 애플의 심사 대상이다.

- **주기 사이에 열렸다 닫힌 연결은 통째로 놓친다.** 짧은 비콘이나 한 번의 다운로드는 안 잡힐 수 있다
- 이벤트에 찍히는 시각은 연결이 일어난 시각이 아니라 **그 연결을 처음 관측한 시각**이다
- established TCP 만 본다. UDP 와 listen 소켓은 목적지가 없거나 상대가 없어 판정에 쓰지 않는다

그래도 패킷만 보는 수집기와 달리 **어느 프로세스가 연결했는지는 알 수 있다.** 그게 이 방식을
고른 이유다.

### macOS 는 eslogger 에 의존한다

`eslogger(1)` man page 에 애플이 직접 적어 둔 문장이 있다. 이것은 API 가 아니며, 출력 형식은
릴리스마다 예고 없이 바뀔 수 있다는 내용이다. 즉 **macOS 업데이트 한 번으로 파싱이 깨질 수 있고,
애플은 그걸 호환성 파기로 취급하지 않는다.**

그 위험을 줄이려고 최상위 `event_type` 숫자 대신 `event` 객체의 멤버 이름으로 종류를 가르고,
필요한 가지만 골라 읽는다. 그래도 구조 자체가 바뀌면 대응할 방법은 없다. macOS 를 올린 뒤에는
이벤트가 계속 오는지 확인해야 한다.

### macOS 전체 디스크 접근 권한은 자동화할 수 없다

애플의 TCC 는 사람이 시스템 설정에서 직접 켜거나 MDM PPPC 프로파일로만 줄 수 있다. 설치
스크립트가 끝나도 이 단계가 남고, **MDM 없이는 무인 배포가 불가능하다.**

권한이 없으면 `eslogger` 가 한 줄도 내지 못한다. 그 상태를 조용히 넘기지 않고 센서가 오류를
올리고 멈추게 해 두었다. 이벤트 0건으로 도는 것보다 뜨지 않는 편이 원인을 찾기 쉽다.

### Kernel-Process 이벤트에는 커맨드라인이 없다

위 `Windows: ETW 세션 하나로 셋 다 받는다` 에 적었다. `OpenProcess` 로 보강하지만 짧게 살다 죽는
프로세스는 실패한다. 실패하면 커맨드라인 자리에 이미지 경로가 들어간다.

### 명령 채널

- 명령 종류는 `kill_process` 하나뿐이다. 셸 스크립트를 내려받아 실행하는 경로는 없다
- 명령 확인 주기는 3초 고정이다. 설정으로 바꿀 수 없다
- 자기 자신과 PID 1 은 종료하지 않는다
- 일치하는 프로세스 중 일부만 종료되면 `KILLED` 가 아니라 `FAILED` 로 보고한다
- 이미 실행한 명령을 다시 받으면 재실행하지 않고 저장해 둔 결과만 다시 보고한다. 기억하는 것은
  최근 256건이고, 넘어가면 통째로 비운다

### 그 밖

- 버퍼는 메모리에만 있다. **에이전트가 죽으면 아직 못 보낸 이벤트는 사라진다.** 디스크 큐는 두지 않았다
- 버퍼가 가득 차면 오래된 이벤트부터 버린다. 버린 수는 종료 로그의 `dropped` 에 찍힌다
- DNS 는 수집하지 않는다. 서버 스키마에 `dns` 타입이 없다. 하트비트 설정에는 `dns` 스위치가 있지만
  어느 플랫폼에서도 그 이름의 센서를 만들지 않는다

## Windows 실기기 검증 절차

Windows 기기가 없어 확인하지 못한 것들이다. **위험한 순서로 정렬했다.** 위쪽이 틀리면 아래는
볼 필요가 없다. 전부 **관리자 권한 PowerShell** 에서 한다(1번만 예외).

가장 위험한 실패 모드를 먼저 적어 둔다. **프로바이더 GUID, keyword 비트, 이벤트 ID 는 컴파일러가
검사해 주지 않는다.** 값이 틀려도 빌드는 통과하고 세션도 열리며, 오류 하나 없이 이벤트만 0건이
된다. 그래서 아래 항목은 대부분 `이벤트가 오는가` 를 묻는다.

### 준비. 서버까지의 경로부터 분리한다

센서를 보기 전에 전송 경로가 사는지 먼저 본다. 여기서 막히면 ETW 문제가 아니다.
`-selftest` 는 진짜 센서 대신 가짜 이벤트 네 종류를 흘려 보낸다.

```powershell
.\edrdog-agent.exe -config C:\ProgramData\EDRdog\config.json -selftest
```

기대: `등록 완료` 와 `수집 시작 sensors=[selftest]` 로그, 그리고 대시보드에 selftest 이벤트 4종.

### 1. 관리자 권한이 없으면 오류로 죽는가

**조용히 0건이 되면 안 된다.** 권한이 없는데 멀쩡히 도는 것처럼 보이는 상태가 이 프로젝트에서
가장 찾기 어려운 고장이었다. 그래서 이 항목은 실패를 확인하는 항목이다.

```powershell
# 일반 사용자 PowerShell 에서 (관리자 아님)
.\edrdog-agent.exe -config C:\ProgramData\EDRdog\config.json
```

- 기대: 아래 오류를 내고 **종료 코드 1 로 죽는다**

  ```
  ETW 세션(EDRdog-Agent)을 열지 못했다. 권한이 없다. 관리자 권한으로 실행하거나
  Performance Log Users 그룹에 넣어라. 서비스로 돌린다면 LocalSystem 이어야 한다: ...
  ```
- 이벤트 0건으로 계속 돌면 그게 버그다

에이전트는 세션 생성 실패를 오류 코드로 갈라 안내한다(`sessionErrorHint`). **안내 문구가 원인과
맞는지도 같이 본다.** 엉뚱한 안내가 나오면 사람이 엉뚱한 곳을 고치게 된다.

| 오류 코드 | 나와야 할 안내 | 일으키는 법 |
|:---|:---|:---|
| `ERROR_ACCESS_DENIED`(5) | 관리자 권한 / `Performance Log Users` 그룹 / LocalSystem 서비스 | 일반 사용자로 실행 |
| `ERROR_ALREADY_EXISTS`(183) | `logman stop EDRdog-Agent -ets` 로 지워라 | 에이전트를 두 개 띄우거나, 아래처럼 세션을 미리 만들어 둔다 |
| 그 밖 | 관리자 권한 안내로 물러난다 | |

```powershell
# 183 을 일부러 내 본다: 같은 이름의 세션을 먼저 만들어 두고 에이전트를 띄운다
logman create trace EDRdog-Agent -p Microsoft-Windows-Kernel-Process 0x10 -ets
.\edrdog-agent.exe -config C:\ProgramData\EDRdog\config.json
logman stop EDRdog-Agent -ets     # 확인 후 정리
```

- 그다음 관리자 권한으로 띄워 세션이 실제로 열리는지 본다

  ```powershell
  logman query -ets      # 다른 창에서
  ```

  기대: `EDRdog-Agent` 세션이 목록에 있고 상태가 Running

### 2. ProcessStart(ID 1)가 실제로 오는가

**이번 설계의 핵심 전제다.** 이 저장소에는 ProcessStop 만 오고 ProcessStart 는 한 건도 오지 않는
실기기 이력이 있다(커밋 `22a5983`). **그 원인은 아직 확인되지 않았다.** 그때는 osquery 로
수집하던 때라 osquery 쪽 사정일 수도 있고 프로바이더 자체의 문제일 수도 있다. 이 에이전트는
구조가 다르니 안 날 수도 있지만, 안 난다고 단정할 근거는 없다.

그래서 에이전트가 Start 와 Stop 을 따로 세어 로그에 남긴다. 그 로그부터 본다.

```powershell
# 에이전트를 띄워 둔 채 다른 창에서
notepad.exe
```

기대하는 로그:

```
level=INFO msg="ETW 수집 상태" processStart=1 processStop=0
```

이 모양이면 그 현상이 재현된 것이다:

```
level=WARN msg="ProcessStop 만 올라오고 ProcessStart 가 한 건도 없다. ..." stops=12
```

- 기대: 대시보드(또는 `events` 토픽)에 `type=process`, `process=notepad.exe` 이벤트 1건
- Start 와 Stop 이 **둘 다 0** 이면 프로바이더가 아예 안 붙은 것이다. 1번으로 돌아간다
- Stop 만 쌓이면 에이전트 문제인지 프로바이더 문제인지 가른다

  ```powershell
  logman create trace T -p Microsoft-Windows-Kernel-Process 0x10 -ets
  # notepad.exe 실행
  logman stop T -ets
  tracerpt T.etl -o T.xml -of XML
  Select-String -Path T.xml -Pattern 'ProcessStart' | Select-Object -First 20
  ```

  여기서도 ProcessStart 가 없으면 프로바이더 쪽 문제이고, 여기엔 있는데 에이전트만 못 받으면
  `etw_windows.go` 의 `eventProcessStart` 상수와 keyword `0x10` 을 본다

### 3. 연결 이벤트에 `PID` 가 실려 오고 그 PID 로 경로가 풀리는가

**이게 안 되면 자체 수집기를 만든 이유 자체가 사라진다.** PID 로 프로세스를 잇지 못하면 예전
구성과 같아진다.

```powershell
# 에이전트를 띄워 둔 채
curl.exe https://example.com
```

- 기대: `type=network`, `destIp` 가 example.com 의 IP, **`process=curl.exe`**
- 사설 IP 로 붙는 연결은 일부러 걸러 내므로 `localhost` 나 사내 주소로 시험하면 아무것도 안 나온다.
  반드시 공인 IP 로 시험할 것
- `process` 가 비어 있으면 둘 중 어디서 끊겼는지 가른다

| 증상 | 볼 곳 |
|:---|:---|
| 이벤트에 `PID` 속성이 없다 | `etw_map.go` 의 `propPID` 상수(`"PID"`)를 매니페스트 이름과 대조. 대소문자가 달라도 걸리게 해 두었으나 이름 자체가 다르면 못 찾는다 |
| `PID` 는 있는데 경로가 안 풀린다 | `QueryFullProcessImageNameW` 가 `PROCESS_QUERY_LIMITED_INFORMATION` 으로 열리는지. `Get-Process curl \| Select-Object Id, Path` 로 대조 |

- 보호된 프로세스(백신 등)는 원래 안 열린다. 그때는 이벤트를 버리지 않고 프로세스명 없이
  내보낸다. 목적지 IP 기반 판정은 살려 두기 위해서다

### 4. `dport` 가 제대로 된 포트로 나오는가

**이건 검증 안 된 가정이다.** 에이전트는 `dport` 에 `ntohs` 를 걸지 않는다. 매니페스트의 outType 이
`win:Port` 이고 MS 문서는 이 값을 `ntohs` 에 넘기라고 하지만, 그건 원시 payload 를 직접 읽을 때
이야기다. 우리는 TDH 가 렌더링해 준 값을 받으므로 이미 호스트 바이트 오더의 십진수라고 보고
변환하지 않는다. **그 가정이 맞는지 보는 항목이다.** 문서만 보고 미리 변환을 넣지 마라.

```powershell
curl.exe https://example.com     # 443 으로 나가야 한다
```

- 기대: `destPort=443`
- **`destPort=47873` 이면 바이트 오더가 뒤집힌 것이다.** 443 은 `0x01BB` 이고 바이트를 뒤집으면
  `0xBB01` = 47873 이다. 이 값이 보이면 `etw_map.go` 의 `MapNetwork` 에서 16비트 스왑을 넣어야 한다
- 다른 포트로도 확인한다. 80 이 뒤집히면 20480(`0x5000`)이다

  ```powershell
  curl.exe http://example.com      # 80 기대
  ```
- `destPort=0` 이면 스왑 문제가 아니라 속성 이름이 다르거나 값이 숫자가 아닌 것이다.
  65535 를 넘는 값은 에이전트가 0 으로 떨어뜨린다

### 5. IPv6 연결(ID 28)의 `daddr` 가 IP 로 파싱되는가

IPv4 와 IPv6 은 이벤트 ID 가 다르다(12 / 28). IPv6 쪽 `daddr` 가 IP 문자열이 아닌 모양으로 오면
**오류 없이 조용히 걸러진다.** 파싱에 실패한 주소는 공인 IP 가 아닌 것으로 보고 버리기 때문이다.

```powershell
curl.exe -6 https://ipv6.google.com
```

- 기대: `type=network` 이벤트가 나오고 `destIp` 가 `2001:...` 형태
- IPv4 는 잡히는데 IPv6 만 하나도 안 잡히면 이 경로가 끊긴 것이다. `daddr` 원본이 어떻게 오는지
  `logman` + `tracerpt` 로 직접 확인한다

  ```powershell
  logman create trace T6 -p Microsoft-Windows-Kernel-Network 0x30 -ets
  curl.exe -6 https://ipv6.google.com
  logman stop T6 -ets
  tracerpt T6.etl -o T6.xml -of XML
  Select-String -Path T6.xml -Pattern 'daddr' | Select-Object -First 10
  ```
- IPv6 이 안 되는 회선이면 이 항목은 확인할 수 없다. 그때는 확인 못 했다고 남겨라

### 6. Kernel-File 의 장치 경로가 감시 경로 필터에 걸리는가

`FileName` 은 `\Device\HarddiskVolume3\Users\a\x.lnk` 같은 **장치 경로**로 오는데, 서버가
내려주는 `watch_paths` 는 `C:\ProgramData\...` 같은 **드라이브 경로**다. 그대로 접두어 비교를 하면
절대 맞지 않는다. 그래서 에이전트가 양쪽에서 볼륨 표기를 떼고 나머지로 견준다. 그 정규화가
실제로 도는지 보는 항목이다.

구독하는 것은 `CreateNewFile(30)` 하나이고 keyword 는 `0x1000` 단독이다. 이벤트 ID 필터와 keyword 는
AND 로 걸리므로 둘 중 하나만 어긋나도 **조용히 0건이 된다.**

```powershell
$p = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp'
New-Item -Path "$p\t.txt" -ItemType File
```

- 기대: `type=file` 이벤트가 나오고 `cmdline` 에 전체 경로가 들어 있음
- **안 나오면 정규화 문제인지 프로바이더 문제인지 가른다.** 감시 경로 밖(`C:\Temp`)에도 파일을
  만들어 본다. 둘 다 안 나오면 프로바이더나 keyword 문제이고, 밖에서는 나오는데 감시 경로에서만
  안 나오면 정규화가 틀린 것이다
- **삭제와 이름 변경은 잡히지 않는 것이 정상이다.** 일부러 구독하지 않는다. 이유는 위
  `Windows: ETW 세션 하나로 셋 다 받는다` 절 참고

  ```powershell
  Remove-Item "$p\t.txt"     # 이벤트가 안 나와야 맞다
  ```
- **사용자별 시작프로그램 경로도 같이 확인해라.** 감시 경로의 `*` 를 경로 한 단계와 맞추는 처리가
  실기기의 장치 경로에서도 먹는지는 확인되지 않았다. 단위 테스트까지만 통과한 부분이다

  ```powershell
  $u = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
  New-Item -Path "$u\t.txt" -ItemType File
  ```

  기대: 전체 사용자용 경로와 똑같이 `type=file` 이벤트가 나온다. 전체 사용자용은 잡히는데 이쪽만
  안 잡히면 `*` 처리가 장치 경로에서 안 걸리는 것이다
- 그다음 부하를 본다. 빌드나 대용량 압축 해제처럼 파일을 많이 만드는 작업을 돌리면서

  ```powershell
  Get-Process edrdog-agent | Select-Object CPU, WorkingSet
  ```

  를 지켜본다. CPU 가 계속 높거나 종료 로그의 `dropped` 가 커지면 keyword 를 더 좁히거나
  파일 센서를 서버 설정에서 꺼야 한다

### 7. 커맨드라인 조회 성공률이 쓸 만한가

`NtQueryInformationProcess` 조회가 자주 실패하면 **T1059 탐지가 약해진다.** detector 가 명령행에서
표식을 찾기 때문이다. 되는지만 보지 말고 얼마나 되는지를 봐야 한다.

```powershell
powershell.exe -NoProfile -Command "Start-Sleep -Seconds 5"
```

- 기대: `type=script`(powershell.exe 는 인터프리터로 분류된다), `cmdline` 에
  `-NoProfile -Command ...` 가 그대로 들어 있음
- `cmdline` 이 이미지 경로와 똑같으면 조회가 실패한 것이다. 정보 클래스 번호 60
  (`ProcessCommandLineInformation`)이 그 Windows 판번호에서 도는지 본다(Windows 8.1 이상)
- 오래 사는 프로세스로 먼저 시험할 것. 즉시 끝나는 프로세스는 원래 실패할 수 있고 그건 알려진 한계다
- **성공률을 재려면** 짧은 프로세스를 여러 번 띄우고 `cmdline` 이 채워진 비율을 본다

  ```powershell
  1..50 | ForEach-Object { Start-Process cmd.exe -ArgumentList '/c','exit' -WindowStyle Hidden }
  ```

  50건 중 몇 건에 인자가 실렸는지 센다. 절반도 안 되면 짧은 프로세스 탐지는 사실상 못 한다고
  봐야 하고, 그 사실을 문서에 남겨야 한다
- 비밀값 옵션(`-Password`, `/token:`, `-EncodedCommand` 등)의 값이 `<redacted>` 로 가려지는지도
  같이 본다

### 8. 서비스로 등록해 부팅 후 자동 기동되는가

지금까지는 콘솔에서 확인한 것이다. 서비스 모드는 SCM 과 대화하는 경로가 따로 있고
(`service_windows.go`), 그 경로도 미검증이다.

```powershell
.\install-windows.ps1 -Server edr.example.com:30443 -EnrollSecret <값>
Get-Service edrdog-agent          # Running 이어야 한다

Restart-Computer
# 부팅 후
Get-Service edrdog-agent          # 로그인 없이도 Running 이어야 한다
```

- 기대: 재부팅 후 사람이 로그인하지 않아도 이벤트가 계속 올라온다
- 서비스가 곧바로 죽으면 SCM 이 Running 보고를 못 받은 것이다. `-service` 플래그가 붙어 등록됐는지
  확인한다

  ```powershell
  sc.exe qc edrdog-agent           # BINARY_PATH_NAME 에 -service 가 있어야 한다
  Get-EventLog -LogName System -Source 'Service Control Manager' -Newest 20
  ```
- **에이전트는 로그를 stderr 로만 낸다.** 서비스로 돌면 그 출력이 갈 곳이 없어 진단이 어렵다.
  서비스가 뜨는데 이벤트만 0건이면 콘솔로 다시 띄워 로그를 직접 봐라. 이건 지금 구조의 약점이고,
  실기기 검증에서 문제가 되면 파일 로깅을 넣어야 한다

### 9. 조치가 실제로 나가는가

```powershell
notepad.exe
# 대시보드에서 그 호스트에 kill 실행, target = notepad.exe
```

- 기대: notepad 가 죽고 결과가 `KILLED`, 메시지에 종료한 pid
- `NO_MATCH` 면 `target` 문자열과 실제 이미지 경로의 매칭 규칙을 본다. Windows 는 대소문자를
  무시하고 비교한다
- 여러 개 떠 있을 때 전부 죽는지, 일부만 죽으면 `FAILED` 로 보고되는지도 같이 본다

## 라이선스

**이 디렉터리(`agent/`)만 GPL-3.0 이다.** 저장소의 나머지는 MIT 다.
전문은 [`LICENSE`](LICENSE), 루트는 [`../LICENSE`](../LICENSE) 에 있다.

ETW 라이브러리 `github.com/0xrawsec/golang-etw` 가 GPL-3.0 이라, 그것을 링크한 에이전트 바이너리는
GPL-3.0 으로 배포해야 한다. 서버(Java 서비스들)는 에이전트와 HTTP 로만 통신하는 별개 프로그램이라
영향을 받지 않는다.

**에이전트 코드를 가져다 쓰면 GPL-3.0 을 따라야 한다.**

이 제약을 없애려면 ETW 를 직접 syscall 로 붙여 그 의존성을 걷어내면 된다. 지금도 프로세스 열거와
종료는 `syscall` 직접 호출로 하고 있으니 불가능한 길은 아니다. 다만 TDH 속성 파싱을 직접 써야 해서
양이 적지 않고, Windows 에서 돌려볼 수 없는 상태에서 그걸 하는 것은 위험하다고 봤다. 그래서 지금은
라이브러리를 쓴다.
