# EDRdog 에이전트

> 엔드포인트에서 프로세스·네트워크·파일 행위를 관찰해 서버로 보내고, 서버가 내린 조치를 실행하는 자체 수집기

Go 로 쓴 단일 실행 파일이다. 대상은 **macOS 와 Windows** 뿐이다.
서버와의 계약은 [`../docs/agent-protocol.md`](../docs/agent-protocol.md) 에 있다.

## 검증 상태

무엇이 확인됐고 무엇이 확인 안 됐는지부터 적는다. 이 구분을 흐리면 문서가 쓸모없어진다.

**확인된 것**

| | |
|:---|:---|
| Go 테스트 | 전 패키지 통과. race 검출기 포함. 패킷 파서는 퍼즈 120만 회 |
| 빌드 | macOS, Windows, Linux 세 플랫폼 통과. `go vet` 통과 |
| 서버까지 왕복 | 실제 바이너리로 확인. 등록 → 하트비트로 설정과 명령 수신 → 이벤트 전송 → 조치 명령 실행 후 결과 보고 |
| 프로세스 종료 | 표적 프로세스가 실제로 종료되는 것까지 확인 |
| macOS 프로세스·파일 | 실기기에서 확인. LaunchDaemon 으로 돌려 `eslogger` 이벤트 수신 |
| macOS 네트워크 | 실기기에서 확인. 연결마다 프로세스 이름이 붙는 것까지 |
| **macOS DNS·TLS** | **실기기에서 확인. 30초에 dns 25건, l7 14건. 아래 참고** |
| 서버 쪽 | Java 테스트 402개 통과 |

macOS 라이브 캡처에서 실제로 잡힌 것이다. 암호화된 TLS 1.3 인데도 어느 프로세스가 어느
도메인에 붙었는지 나온다.

```json
{"type":"l7","process":"sensor.test","destIp":"172.66.147.243","destPort":443,
 "domain":"example.com","detail":"{\"alpn\":[\"h2\",\"http/1.1\"],\"tlsVersion\":\"TLS 1.3\"}"}
```

다만 **TLS 이벤트에 프로세스가 붙는 비율은 14건 중 6건이었다.** 우리가 낸 접속과 일반 응용
프로그램에는 붙었고, 빠진 여덟 건은 전부 Apple 시스템 데몬이었다. root 인데도 SIP 가 보호하는
프로세스의 소켓을 못 읽는 것으로 의심하지만 **확인된 것은 아니다.** 탐지 대상은 사용자가 실행한
프로그램이라 실용적인 손해는 작지만, "항상 붙는다" 고 말할 수는 없다.

**확인 안 된 것 (전부 Windows 다)**

- **Windows ETW 센서를 실제 Windows 기기에서 한 번도 돌려보지 않았다.** 크로스 빌드와 순수 로직
  단위 테스트까지가 전부다
- **상수가 틀려도 빌드는 통과하고 조용히 0건이 된다. 이게 가장 위험하다.** 프로바이더 GUID,
  keyword 비트, 이벤트 ID 는 컴파일러가 검사해 주지 않는다. 값 하나가 어긋나면 오류 없이
  이벤트만 안 온다
- **pktmon 으로 TLS SNI 를 받는 경로 전체가 미검증이다.** 이벤트 160 의 필드 배치는 Microsoft 의
  NetMon 파서와 드라이버 헤더 두 곳을 대조해 잡았지만 실기기에서 확인한 것은 아니다. 어긋나면
  `sizeMismatch` 로 잡히게 해 두었다. **Windows Defender 가 pktmon 조작을 막을 가능성이 이 경로에서
  가장 큰 위험이다.** 공격 기법으로 공개된 방식이라 휴리스틱 탐지가 실재한다
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

### Windows: TLS SNI 만 패킷을 보고, 그 패킷도 같은 세션으로 받는다

`l7` 이벤트(TLS ClientHello 의 SNI)는 커널 이벤트로는 알 수 없다. 어느 도메인에 접속했는지는
패킷 안에만 있다. 그래서 Windows 에서도 패킷을 봐야 하는데, **드라이버는 설치하지 않는다.**
Npcap 은 라이선스가 재배포를 금지한다. 대신 Windows 10 2004 이후와 Windows 11 에 인박스로 들어
있는 `pktmon` 을 쓴다.

**ETW 프로바이더를 켜는 것만으로는 캡처가 시작되지 않는다.** `pktmon.sys` 가 먼저 시작돼야 이벤트를
만든다. 프로바이더만 켜면 세션도 붙고 오류도 없는데 이벤트가 0건이다. 드라이버를 시작하는 길은
셋인데, 실제로 쓸 수 있는 것은 하나뿐이었다.

| 방법 | 왜 안 쓰나 / 쓰나 |
|:---|:---|
| 문서화된 Win32 API (`PacketMonitorCreateLiveSession` 등, `Pktmonapi.dll`) | MS 문서의 요구 사항 표에 **Minimum supported client 가 비어 있다.** 서버는 Windows Server 2022 6b 이상이라고만 적혀 있어, 대상인 Windows 10/11 클라이언트에 있다는 근거가 없다 |
| `Pktmonapi.dll` 의 옛 export (`PktmonStart` 등) 또는 `\\.\PktMonDev` IOCTL | 둘 다 **문서가 없다.** 인자 구조를 리버스 엔지니어링 글에서 짐작해 넣는 셈인데, 틀려도 오류가 아니라 조용한 0건으로 나타난다 |
| `pktmon.exe` 를 부른다 | 인자와 동작이 MS 문서에 그대로 있다. **이걸 쓴다** |

외부 프로세스를 띄우는 것은 마지막 수단이지만, 남은 둘이 "문서가 없어 틀렸는지도 모르는 채 0건"
으로 끝날 수 있는 길이라 이쪽을 골랐다. 부르는 것은 시작과 끝 각각 두 번뿐이고, **이벤트는 우리
ETW 세션에서 직접 받는다.** 즉 데이터 경로에는 외부 프로세스가 없다.

```
pktmon filter remove                                        # 남아 있던 필터를 먼저 지운다
pktmon filter add EDRdog-TLS -t TCP -p 443                  # 커널에서 거른다
pktmon start --capture --comp nics --pkt-size 2048 \
             --flags 0x10 --log-mode memory --file-size 1 --file-name %TEMP%\edrdog-pktmon.etl
```

- `--flags 0x10` 은 프레임 바이트(raw packet)다. `--pkt-size` 기본값 128 로는 ClientHello 의 SNI
  확장이 잘려 도메인을 못 뽑는다. macOS 캡처의 snaplen 과 같은 2048 을 쓴다
- `--comp nics` 는 같은 패킷이 컴포넌트마다 한 번씩 올라오는 것을 막는다. 기본값 `all` 이면
  한 패킷이 NIC, vSwitch 등에서 여러 번 보고돼 양이 몇 배가 된다
- `--log-mode memory --file-size 1` 은 pktmon 자신의 로그를 1MB 메모리에 두고 stop 할 때만 파일로
  쓰게 한다. 우리는 그 파일을 읽지 않지만 pktmon 이 로그 대상 없이는 시작하지 않아서 두는 것이고,
  닫을 때 지운다

프레임은 프로바이더 `Microsoft-Windows-PktMon` 의 **이벤트 160** 에 실려 온다. keyword 는
**`0x10`(Payload)** 이고, 이걸 빼면 메타데이터만 오고 프레임 바이트가 비어 온다. 이 프로바이더도
`EDRdog-Agent` **같은 세션**에 붙인다. 별도 세션이면 버퍼 풀과 플러시 주기가 따로 놀아 연결
이벤트와 패킷의 도착 순서가 더 흔들리는데, 아래 프로세스 귀속이 그 순서에 달려 있다.

**DNS 는 이 경로로 뽑지 않는다.** Windows 의 DNS 는 이미 ETW 의 DNS-Client 프로바이더로 받고 있어서
패킷에서 또 뽑으면 같은 질의가 두 번 올라간다. `L7Sensor` 는 UDP 53 을 보면 `dns` 이벤트를 내도록
되어 있으므로, 그 경로가 아예 안 타게 **커널 필터를 TCP 443 하나만 걸었다.** UDP 53 프레임은 애초에
올라오지 않는다. 시작할 때 `pktmon filter remove` 로 남아 있던 필터를 전부 지우는 것도 같은 이유다.
필터 목록은 시스템 전체에 하나뿐이라, 앞서 죽은 우리 프로세스나 다른 도구가 남긴 53번 필터가
살아 있으면 그 막음이 뚫린다. Windows 에서 `L7Sensor` 를 붙일지 결정할 때 `dns` 스위치를 보지 않고
`l7` 스위치만 보는 것도 같은 판단이다.

**프레임이 이더넷인지 IP 헤더부터인지는 이벤트가 알려 준다.** 이벤트 160 의 `PacketType` 필드가
`1 = Ethernet`, `3 = IP` 다(드라이버 헤더 `pktmonnpik.h` 의 `PKTMON_PACKET_TYPE`). 캡처가 그 값을
보고 raw IP 프레임에는 14바이트 이더넷 헤더를 지어 붙여, 센서에는 언제나 이더넷 프레임 한 가지
모양만 넘긴다. MAC 자리는 0 이고 `packet.Parse` 는 EtherType 두 바이트만 읽으므로 지어낸 값이
판단에 쓰이지 않는다. **링크 종류를 잘못 짚어 조용히 0건이 되는 실패 모드를 아예 없애려는 것이다.**

#### SNI 에 프로세스를 붙이는 방법이 macOS 와 다르다

macOS 는 ClientHello 를 본 그 순간 열려 있는 소켓을 전부 훑어 주인을 찾는다. Windows 는 그럴 필요가
없다. **`Microsoft-Windows-Kernel-Network` 연결 이벤트가 이미 PID 를 실어 준다.** 그 값을
`FlowOwners` 에 잠깐 기억해 두었다가 SNI 가 올 때 `(로컬 포트, 상대 IP, 상대 포트)` 로 이어 붙인다.

| | 값 | 이유 |
|:---|:---|:---|
| TTL | 60초 | ETW 실시간 세션은 프로세서마다 버퍼를 따로 두고 기본 1초 주기로 비워서 만들어진 순서와 배달 순서가 다를 수 있다. 반대로 60초 안에 동적 포트 16384개를 한 바퀴 돌리려면 초당 273개 연결을 그 시간 내내 유지해야 하는데 단말에서 나올 수치가 아니다 |
| 항목 상한 | 8192 | 바깥 입력으로 커지는 맵이다. 넘으면 만료된 것부터 지우고, 그래도 모자라면 통째로 버린다 |
| 로컬 포트만으로 물러나기 | **안 한다** | 최대 60초 전의 기억이라, 포트만 맞춰 답하면 이미 닫힌 연결의 프로세스를 새 연결에 붙일 수 있다. 틀린 프로세스는 빈 값보다 나쁘다 |

프로토콜상으로는 연결 이벤트가 ClientHello 보다 **반드시 먼저 생긴다.** ClientHello 는 3-way
handshake 가 끝난 뒤에 나가고 연결 이벤트는 커널이 SYN 을 낼 때 나므로 최소 1 RTT 차이가 난다.
문제는 도착 순서다. 그래서 두 가지를 했다.

- 두 프로바이더를 같은 세션에 넣었다. 버퍼 풀과 타임스탬프 기준계가 하나가 된다
- **연결 기억과 프레임 전달을 둘 다 ETW 콜백 스레드에서 한다.** 연결 기억을 이벤트 채널을 읽는
  고루틴에서 했다면, ETW 가 순서를 지켜 보내 줘도 우리 고루틴 둘이 그 순서를 다시 흐트러뜨린다

**조회가 빗나갔을 때 미뤘다가 다시 시도하지는 않는다.** 적중률은 오르겠지만 `Lookup` 은 `L7Sensor` 의
단일 고루틴에서 동기로 불리므로, 여기서 기다리면 그동안 캡처 큐가 쌓이고 넘치면 프레임을 통째로
잃는다. 빗나감이 몇 개만 몰려도 몇 초가 서는데, 프로세스 이름 하나 얻자고 관측을 멈추는 것은
바꿔치기가 맞지 않는다. 대신 **적중률을 1분마다 로그에 남긴다**(`SNI 프로세스 귀속 상태 hit=.. miss=..`).
실기기에서 이 비율이 낮게 나오면 그때 미루기를 넣을지 판단하면 된다. **지금 이 비율이 얼마일지는
추정하지 않았다.** 실기기 데이터가 없다.

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
| macOS | `eslogger` (process 또는 file 이 켜져 있으면), `netsnap` (network 가 켜져 있으면), `l7` (dns 또는 l7 이 켜져 있으면) |
| Windows | `etw` 하나. 세 종류를 세션 하나로 받는다 |
| 그 외 | 없음. 기동을 거부한다 |

**macOS 의 `l7` 만 예외적으로 없어도 기동한다.** 이 센서 하나가 `dns` 와 `l7` 이벤트를 같이 낸다.
BPF 장치를 열려면 root 가 필요하고 기본 경로가 이더넷이어야 하는데, 그 조건이 안 맞는 상황이
흔하다. 그때 프로세스와 파일 관측까지 같이 잃는 것이 손해가 더 크다고 봤다. 대신 **못 연 이유는
반드시 로그에 남는다.** 아래 줄이 보이면 패킷 수집이 안 도는 것이다.

```
level=ERROR msg="패킷 캡처를 열지 못해 dns/l7 수집을 건너뛴다" err=...
```

## 설치

두 스크립트 모두 서버에서 인증서를 직접 받아 저장한다. 관리자가 PEM 파일을 따로 전달할 필요가 없다.
여러 번 실행해도 안전하다.

### macOS

명령 하나로 끝낸다. 빌드부터 등록 확인까지 이어서 한다.

```bash
sudo ./agent/packaging/bootstrap-macos.sh \
  --server edr.example.com:30443 --enroll-secret <발급받은 값>
```

시크릿을 아직 안 받았으면 대신 받아 오게 할 수 있다. 비밀번호는 인자로 받지 않고 물어본다.
인자로 주면 `ps` 에 그대로 보이고 셸 기록에도 남는다.

```bash
sudo ./agent/packaging/bootstrap-macos.sh \
  --server edr.example.com:30443 --email me@example.com --api-key <프론트 키>
```

`--api-key` 가 필요한 이유는 `/api/tenant` 가 `X-API-Key` 예외 경로가 아니라서다
(`ApiKeyPolicy.EXEMPT_PREFIXES`). 반면 `/api/agent/` 는 예외라, 설치가 끝난 뒤 에이전트
자신은 이 키 없이 `enroll_secret` 과 `node_key` 만으로 붙는다.

중간에 **전체 디스크 접근 권한**에서 한 번 멈춘다. 이건 자동화가 안 된다. 애플의 TCC 는
사람이 직접 켜거나 MDM 프로파일로만 줄 수 있다. 스크립트가 그 설정 창을 열어 주고, 켜고
Enter 를 누르면 이어서 재시작하고 등록됐는지까지 확인한다.

> 파일 선택창이 뜬 **다음에** `Cmd+Shift+G` 를 눌러야 경로 입력이 먹는다. 목록에 대고 바로
> 누르면 안 먹는다.

마지막 확인은 로그에서 `등록 완료` 줄을 찾는 것으로 한다. 30 초 안에 안 보이면 실패로
끝내고 어디를 볼지 알려준다. `ERR_NOT_PERMITTED` 가 보이면 권한이 아직 안 켜진 것이라
그것만 따로 짚어 준다. 이 두 줄을 보는 이유는, 프로세스가 떠 있다는 것과 서버에 붙었다는
것이 전혀 다른 말이기 때문이다.

#### 단계별로 하고 싶으면

`install-macos.sh` 는 설치만 한다.

```bash
cd agent
go build -o packaging/edrdog-agent ./cmd/edrdog-agent
sudo ./packaging/install-macos.sh --server edr.example.com:30443 --enroll-secret <발급받은 값>
```

바이너리를 `/usr/local/bin/edrdog-agent` 에 놓고, 설정을 `/etc/edrdog/config.json` 에 쓰고,
`/Library/LaunchDaemons/com.edrdog.agent.plist` 로 등록해 부팅 시 자동 기동시킨다.

```bash
sudo launchctl print system/com.edrdog.agent   # 상태
tail -f /var/log/edrdog/agent.log              # 로그
```

**터미널에서 직접 실행하지 마라.** LaunchDaemon 으로 돌려야 한다. 터미널에서 띄우면 TCC 주체가
에이전트가 아니라 터미널 앱이 되어, 터미널에 권한을 준 셈이 되고 `ERR_NOT_PERMITTED` 가 난다.

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

### 파일 해시는 실행 이미지에만 붙인다

`sha256` 은 process/script 이벤트에만 싣고 **file 이벤트에는 싣지 않는다.**

파일 생성 이벤트는 파일이 만들어진 순간에 온다. 그때 읽으면 **아직 다 쓰이지 않은 내용의 해시**가
나올 수 있다. 그 값은 알려진 악성코드 해시와 영원히 맞지 않으면서 "해시를 확인했다" 는 착각을
주므로 없는 것보다 나쁘다. 삭제 이벤트는 파일이 이미 없고, 이름 변경도 원본이 계속 쓰이는 중일
수 있어 사정이 같다. 우리가 감시하는 자동실행 경로의 파일은 대개 작고 한 번에 쓰이지만,
"대개" 를 근거로 틀린 값을 보낼 수는 없다.

실행 이미지는 사정이 다르다. exec 시점의 파일은 커널이 이미 읽어 올린 것이라 반드시 완성돼
있다. 그래서 **자동실행 경로에 놓인 파일도 그것이 실제로 실행되는 순간에는 해시가 붙는다.**
잃는 것은 "놓이기만 하고 아직 실행되지 않은 파일의 해시" 뿐이다.

- 기다렸다 뜨거나 크기가 두 번 연속 같을 때만 뜨는 방법도 있지만, 둘 다 파일 이벤트마다 대기가
  붙는다. 얻는 것에 비해 비싸서 고르지 않았다
- 크기 상한은 32MB 다. 그보다 큰 파일은 해시 없이 나간다. 실행 파일은 대개 수 MB 이고, 그보다
  큰 것은 데이터나 컨테이너 이미지지 해시로 조회할 대상이 아니다. 상한이 없으면 몇 GB 짜리
  파일 하나가 뜰 때마다 디스크를 그만큼 읽는다
- 해시는 `(경로, 크기, 수정시각)` 으로 캐시한다. 셋이 같으면 같은 내용으로 본다. 항목 수 상한은
  4096 이고 넘으면 통째로 비운다
- 전체 경로를 모르는 이벤트에는 해시를 붙이지 않는다. Windows 의 `ImageName` 은 파일명만 오는
  경우가 있는데, 그것을 그대로 열면 에이전트의 작업 디렉터리 기준 상대 경로가 되어 엉뚱한 파일의
  해시가 붙는다
- 해시를 구하지 못한 횟수는 1분마다 로그에 `실행 파일 해시 상태` 로 남는다. 해시가 전부 비어
  있을 때 원인이 권한인지 크기 상한인지 가리려면 이 값이 필요하다
- **이 경로는 실기기에서 돌려 본 적이 없다.** 단위 테스트까지가 전부다

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
- **macOS 의 dns 이벤트에는 프로세스가 붙지 않는다.** 모든 DNS 질의가 `mDNSResponder` 를 거쳐
  나가서, 소켓 주인을 찾으면 언제나 그것이 나온다. 진짜 질의한 앱이 아니다. 틀린 값을 채우면
  조사하는 사람이 그걸 믿고 엉뚱한 결론을 내므로 일부러 비운다. 진짜 질의자는 같은 시각의
  `l7` 이벤트나 `network` 이벤트에서 찾아야 한다
- **Windows 의 dns 이벤트에는 `protocol` 이 없다.** ETW 의 DNS-Client 프로바이더가 질의를 UDP 로
  보냈는지 TCP 로 보냈는지 알려 주지 않는다. 대개 UDP 지만 지어내면 조사하는 사람이 그 값을
  관측 결과로 믿는다. 반대로 macOS 의 dns 이벤트에는 `pid` 가 없다. 위와 같은 이유다
- **DNS 는 응답만 이벤트로 낸다.** 질의와 응답을 둘 다 내면 같은 도메인이 두 번 올라간다.
  응답 쪽을 고른 이유는 어느 IP 로 풀렸는지까지 담기 때문이다. 없는 도메인은 서버가 NXDOMAIN
  응답을 주므로 잡히지만, **응답이 아예 오지 않은 질의는 놓친다**(DNS 서버가 닿지 않거나 타임아웃)
- 패킷 캡처는 **이더넷 인터페이스에서만** 된다. 기본 경로가 VPN(utun)이면 링크 종류가 달라
  오류를 내고 멈춘다. 필터가 이더넷 오프셋 기준이라 그대로 붙이면 조용히 0건이 되기 때문이다
- IPv6 확장 헤더가 붙은 패킷은 BPF 필터를 통과하지 못한다. 확장 헤더는 길이가 가변이라 전송 계층
  위치를 고정 오프셋으로 잡을 수 없다. 실제 DNS/TLS 트래픽에 붙는 일이 거의 없어 감수했다
- TLS 는 **ClientHello 의 SNI, 버전, ALPN 까지만** 본다. 인증서는 TLS 1.3 에서 암호화돼 평문
  캡처로 읽을 수 없다. 페이로드는 어떤 경우에도 저장하지 않는다

## macOS 실기기 검증 절차

패킷 캡처(`dns`, `l7` 센서)는 **root 와 실제 네트워크가 있어야** 돌아간다. 그래서 보통의
`go test ./...` 로는 확인되지 않는다. 확인용 테스트를 opt-in 으로 넣어 두었다.

```bash
cd agent
go test -c -o /tmp/sensor.test ./internal/sensor
sudo EDRDOG_LIVE=1 /tmp/sensor.test -test.run TestLiveCapture -test.v
```

테스트 바이너리를 먼저 만들고 그걸 `sudo` 로 돌리는 이유는 `sudo go test` 가 root 의 PATH 와
빌드 캐시를 쓰기 때문이다. **컴파일은 사용자 권한으로 하고 실행만 root 로 한다.** 기본 30초
동안 돌고, `EDRDOG_LIVE_SECONDS` 로 늘릴 수 있다.

**트래픽은 테스트가 직접 만든다.** 사람이 브라우저를 여는 것에 기대면 이벤트가 0건일 때
캡처가 고장난 것인지 트래픽이 없었던 것인지 구분할 수 없다. 테스트가 스스로 DNS 질의(캐시를
피하려고 난수 이름을 쓴다)와 TLS 접속을 낸 뒤 그것이 이벤트로 돌아오는지 본다.

확인 항목은 넷이다. **위쪽이 틀리면 아래는 볼 필요가 없다.**

| # | 보는 것 | 실패하면 의심할 곳 |
|:--|:---|:---|
| 1 | 시작 로그의 `buffer` 가 `524288` 인가 | `4096` 이면 `BIOCSBLEN` 이 안 먹은 것이다. 부하 시 패킷을 크게 잃는다 |
| 2 | `dns` 이벤트가 오고 `domain` 이 질의한 이름인가 | BPF 필터의 UDP 53 양방향 판정, `bpf_hdr` 쪼개기 |
| 3 | `l7` 이벤트가 오고 `domain` 이 접속한 SNI 인가 | BPF 필터의 TCP 443 판정, `Assembler` 배선 |
| 4 | `l7` 이벤트의 `process` 가 비어 있지 않은가 | `ProcOwner` 의 libproc 조회(`insi_lport` 를 로컬 포트로 읽는 부분) |

2번이 제일 먼저 깨지는 자리다. `bpf_hdr` 쪼개기를 틀리면 **첫 패킷만 살고 두 번째부터 전부
쓰레기가 된다.** macOS 의 `BPF_ALIGNMENT` 는 `sizeof(int32_t)` 라 4 인데, FreeBSD 와 같은 8 로
맞추면 정확히 이 증상이 난다. 그래서 테스트가 접속을 여러 번 내서 한 `read` 에 여러 패킷이
담기도록 한다.

4번은 접속을 낸 것이 테스트 바이너리 자신이라 **반드시 찾혀야 한다.** 비어 있으면 조회 로직이
틀린 것이지 타이밍 문제가 아니다.

권한이 없으면 조용히 0건이 되지 않고 아래처럼 죽는다. 이것도 확인 항목이다.

```
/dev/bpf0 를 열 권한이 없다. 패킷 캡처는 root 로 실행해야 한다: permission denied
```

기본 경로가 VPN(utun)이면 이더넷이 아니라서 아래 오류로 멈춘다. 필터가 이더넷 오프셋 기준이라
그대로 붙이면 0건이 되는데, 그것보다 이유를 말하고 멈추는 쪽을 골랐다.

```
utun4 는 이더넷이 아니다(DLT 0). 이 캡처는 이더넷 인터페이스만 다룬다
```

## Windows 실기기 검증 절차

Windows 기기가 없어 확인하지 못한 것들이다. **위험한 순서로 정렬했다.** 위쪽이 틀리면 아래는
볼 필요가 없다. 전부 **관리자 권한 PowerShell** 에서 한다(1번만 예외).

가장 위험한 실패 모드를 먼저 적어 둔다. **프로바이더 GUID, keyword 비트, 이벤트 ID 는 컴파일러가
검사해 주지 않는다.** 값이 틀려도 빌드는 통과하고 세션도 열리며, 오류 하나 없이 이벤트만 0건이
된다. 그래서 아래 항목은 대부분 `이벤트가 오는가` 를 묻는다.

**단위 테스트가 통과한다고 안심하지 마라.** macOS 캡처에서 실제로 겪은 일이다. 커널은 BPF 헤더
길이로 18 을 보내는데 코드는 20 을 기대했고, 테스트 픽스처도 20 으로 만들어져 있었다. 코드와
픽스처에 같은 오해가 들어가 있으니 테스트는 멀쩡히 통과하고 실기기에서만 모든 패킷이 버려졌다.
오류도 로그도 없어서 원인을 찾는 데 오래 걸렸다.

교훈은 셋이다.

- 픽스처를 만든 사람과 코드를 만든 사람이 같으면 그 검증은 반쪽이다. **값의 근거를 매니페스트나
  공식 문서에서 따로 확인해라**
- 구조체를 통째로 캐스팅하지 마라. 패딩이 끼어들면 조용히 어긋난다. 필드 오프셋을 직접 읽어라
- **조용히 버리는 자리를 만들지 마라.** 버리는 조건마다 왜 버렸는지 셀 수 있게 하거나 로그를
  남겨야 한다. 이 프로젝트에서 가장 찾기 어려운 고장이 전부 그 모양이었다

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

### 10. TLS SNI 가 pktmon 으로 잡히는가

**번호는 뒤지만 위험도는 위쪽과 같은 급이다.** 1, 2번(세션이 열리고 이벤트가 오는가)이 통과한
다음에 볼 항목이라 여기 두었을 뿐이고, 이 경로는 실기기에서 확인된 것이 하나도 없다.

macOS 쪽처럼 **opt-in 라이브 테스트**를 만들어 두었다. 사람이 브라우저를 여는 것에 기대면
아무것도 안 나왔을 때 캡처가 고장난 것인지 트래픽이 없었던 것인지 구분할 수 없어서, 테스트가
스스로 TLS 접속을 낸 뒤 그것이 이벤트로 돌아오는지 본다.

```powershell
cd agent
go test -c -o C:\Temp\sensor.test.exe .\internal\sensor
# 관리자 PowerShell 에서
$env:EDRDOG_LIVE=1; C:\Temp\sensor.test.exe -test.run TestLivePktMonCapture -test.v
```

컴파일은 사용자 권한으로 하고 실행만 관리자로 한다. 시간을 늘리려면 `EDRDOG_LIVE_SECONDS` 를 준다
(기본 45초).

이 테스트가 단언하는 것은 넷이다.

| # | 단언 | 깨지면 의심할 곳 |
|:---|:---|:---|
| 1 | `l7` 이벤트가 한 건이라도 나오는가 | 아래 표의 이유별 건수를 먼저 본다 |
| 2 | 접속한 SNI 가 그 이벤트에 있는가 | 캡처는 살아 있고 필터나 `Assembler` 배선이 문제 |
| 3 | `l7` 이벤트에 `process` 가 붙는가 | Kernel-Network 연결 이벤트, `FlowOwners` 의 조인 키(`sport`/`daddr`/`dport`) |
| 4 | `dns` 이벤트가 **이 경로로는** 안 나오는가 | pktmon 필터에 53번이 남아 있는 것 |

4번은 테스트가 ETW 의 `dns` 센서를 꺼 놓고 돌리므로, 거기서 나온 `dns` 이벤트는 반드시 패킷
경로에서 온 것이다. 0건이어야 한다.

1번이 깨졌을 때는 로그의 pktmon 상태 줄(`pktmon 캡처 상태 accept=.. sizeMismatch=.. ...`)이 어디서
끊겼는지 말해 준다. **이 줄을 보라고 만든 것이다.** 모든 값이 0 이면 이벤트 자체가 안 온 것이다.

| 쌓이는 이유 | 뜻 | 볼 곳 |
|:---|:---|:---|
| 전부 0 | 이벤트가 한 건도 안 왔다 | `pktmon status` 로 캡처가 도는지, 프로바이더 이름이 풀렸는지 |
| `empty` | 메타데이터만 오고 프레임 바이트가 없다 | keyword `0x10`(Payload)과 `--flags 0x10` |
| `sizeMismatch` | **우리가 읽는 필드 위치가 이 Windows 판과 어긋났다** | `pktmon.go` 의 `pktMonOffLoggedSize`(32)와 `pktMonHeaderLen`(34) |
| `linkType` | 이더넷도 raw IP 도 아닌 프레임이다 | `packetType2`(WiFi) 가 같이 쌓였는지 |
| `inbound` 만 쌓이고 `accept` 는 0 | 나가는 패킷을 하나도 못 봤다 | `dirTag` 별 건수. 우리가 In/Rx/Ingress 로 아는 값만 오고 있는지 |
| `queueFull` | 센서가 밀린다 | 양이 너무 많다. `--comp nics` 가 먹었는지 |

`sizeMismatch` 가 이 항목에서 가장 중요한 신호다. 이벤트 160 의 필드 배치는 Microsoft 의 NetMon
파서(`etl_Microsoft-Windows-PktMon-Events.npl` 의 `PktMon_FramePayload`)와 드라이버 헤더의
`PKTMON_EVT_STREAM_METADATA` 두 곳을 대조해 잡았지만, **실기기에서 확인한 것은 아니다.** 어긋나면
`34 + LoggedPayloadSize != 이벤트 길이` 가 되어 여기 잡힌다. 그래서 조용한 0건 대신 이유 있는
0건이 된다.

#### 눈으로 같이 볼 것

- **프레임이 이더넷인가 IP 헤더부터인가.** 로그의 `packetType1`(Ethernet) 과 `packetType3`(IP) 중
  어느 쪽이 쌓이는지 본다. 코드는 둘 다 처리하지만, 어느 쪽이 오는지는 아무도 모른다
- **`dirTag` 로 무엇이 오는가.** `dirTag4`(Tx) / `dirTag2`(Out) / `dirTag6`(Egress) 중 어느 것이
  실제로 오는지 본다. 지금은 In/Rx/Ingress 만 버리고 모르는 값은 통과시키는데, 실제로 오는 값이
  확인되면 나가는 쪽만 남기도록 조일 수 있다
- **SNI 에 프로세스가 붙는 비율.** 로그의 `SNI 프로세스 귀속 상태 hit=.. miss=..` 를 본다.
  이 테스트는 자기 자신이 접속을 내므로 **반드시 붙어야 한다.** 하나도 안 붙으면 조인 키가 틀린
  것이지 타이밍 문제가 아니다. 절반쯤 붙으면 그때가 도착 순서 문제이고, 그러면 `FlowOwners` 에
  미뤘다 재시도를 넣을지 판단한다
- **부하.** `pktmon` 캡처가 도는 동안 CPU 와 메모리를 본다

  ```powershell
  Get-Process edrdog-agent | Select-Object CPU, WorkingSet
  ```

  `queueFull` 이 쌓이면 커널 필터가 제대로 안 걸린 것이다. `pktmon filter list` 로 우리 필터
  하나(`EDRdog-TLS`)만 있는지 본다

#### 관리자 권한 없이 실행하면 명확한 오류로 죽는가

에이전트 전체는 ETW 세션을 못 열어 먼저 죽는다(1번 항목). pktmon 만 따로 보려면 일반 사용자
PowerShell 에서:

```powershell
pktmon start --capture
```

- 기대: 권한 오류 메시지. 에이전트는 이 출력을 그대로 오류에 담아 `pktmon 캡처를 열지 못해 l7
  수집을 건너뛴다` 로 남기고, **에이전트를 죽이지는 않는다.** 나머지 센서는 멀쩡하기 때문이다
- 이 로그가 안 보이는데 `l7` 이벤트도 없으면 캡처는 열렸고 다른 곳이 문제다

#### Windows Defender 가 pktmon 조작을 차단하는가 (**가장 큰 위험**)

pktmon 을 캡처 도구로 쓰는 것은 **공격 기법으로 공개된 방식이다.** 휴리스틱 탐지에 걸릴 가능성이
실재한다. 이건 코드로 어떻게 할 수 있는 문제가 아니라 실기기에서 확인해야만 아는 것이다.

```powershell
# 에이전트를 30분쯤 돌린 뒤
Get-MpThreatDetection | Select-Object -First 20
Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -MaxEvents 50 |
  Where-Object { $_.Message -match 'pktmon|edrdog' }
```

- **차단당하면** `pktmon start` 가 실패하거나, 성공한 뒤 캡처가 조용히 멈춘다. 후자가 더 나쁘다.
  1분마다 나오는 `pktmon 프레임을 한 건도 넘기지 못했다` 경고가 그 신호다
- 에이전트 바이너리와 `pktmon.exe` 호출이 ASR 규칙에 걸리는지도 본다

  ```powershell
  Get-MpPreference | Select-Object AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions
  ```
- 막히면 선택지는 둘이다. 배포 환경에 예외를 넣거나, TLS SNI 수집을 Windows 에서 포기하는 것이다.
  **포기해도 나머지는 그대로 돈다.** `l7` 센서만 안 붙는다

#### 끝난 뒤 정리됐는지

에이전트를 멈춘 뒤 남은 것이 없어야 한다. 남기면 다음 실행이 그걸 물려받고, 특히 필터가 남으면
우리가 걸지 않은 조건으로 패킷이 올라온다.

```powershell
pktmon status         # 캡처가 멈춰 있어야 한다
pktmon filter list    # EDRdog-TLS 가 없어야 한다
dir $env:TEMP\edrdog-pktmon.etl   # 없어야 한다
```

- 에이전트를 `taskkill /f` 로 강제 종료하면 정리 코드가 안 돈다. 그때는 위 셋이 남는데,
  다음 실행이 `pktmon filter remove` 로 먼저 지우므로 필터는 회복된다. 캡처와 파일은 손으로 치운다

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
