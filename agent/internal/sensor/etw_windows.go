//go:build windows

package sensor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/0xrawsec/golang-etw/etw"

	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/event"
)

// 이 파일은 배선만 한다. 판정에 관여하는 로직은 전부 etw_map.go 에 있다.
// Windows 기기 없이 개발하므로, 여기에 로직을 두면 검증할 방법이 없다.

// etwSessionName 은 우리가 여는 실시간 ETW 세션 이름이다.
// 커널 로거("NT Kernel Logger")는 쓰지 않는다. 시스템 전체에 하나뿐이라 다른 도구와 부딪히고,
// 예전 osquery 수집이 조용히 0건이 된 원인이 바로 그 세션이었다(아래 프로바이더 주석 참고).
const etwSessionName = "EDRdog-Agent"

// 프로바이더 GUID 는 여기에 적어 두지 않는다.
//
// 이벤트가 어느 프로바이더에서 왔는지 가릴 때 쓸 GUID 는 프로바이더를 켤 때 라이브러리가
// 이름으로 풀어 준 값을 그대로 들고 있다가 쓴다. GUID 를 손으로 적어 두면 켤 때 쓰는 이름과
// 견줄 때 쓰는 GUID 가 따로 놀 수 있고, 어긋나도 오류가 나지 않고 조용히 0건이 된다.
// Windows 기기 없이 개발하는 처지에서는 그 실패 모드를 아예 만들지 않는 편이 낫다.
//
// 참고로 매니페스트 값은 Kernel-Process {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716},
// Kernel-Network {7DD42A49-5329-4832-8DFD-43D979153A88},
// Kernel-File {EDD08927-9CC4-4E65-B970-C2560FB5C289} 이다.

// 우리가 받을 이벤트 ID.
const (
	eventProcessStart = 1 // Kernel-Process ProcessStart
	eventProcessStop  = 2 // Kernel-Process ProcessStop

	eventTCPConnectV4 = 12 // Kernel-Network TCP 연결 시도(IPv4)
	eventTCPConnectV6 = 28 // Kernel-Network TCP 연결 시도(IPv6). IPv4 ID + 16 이다

	eventCreateNewFile = 30 // Kernel-File CreateNewFile

	eventDNSQueryCompleted = 3008 // DNS-Client 질의 완료. 3006(질의 발신)은 받지 않는다
)

// etwProvider 는 센서 스위치 하나와 그에 맞는 프로바이더 설정이다.
//
// spec 형식은 golang-etw 의 ParseProvider 규약이다:
//
//	이름:EnableLevel:이벤트ID들:MatchAnyKeyword:MatchAllKeyword
//
// 이벤트 ID 를 적으면 커널 쪽 필터로도 걸리므로, 우리 콜백까지 올라오는 양 자체가 준다.
type etwProvider struct {
	sensor string
	spec   string
}

var etwProviders = []etwProvider{
	// ProcessStart(1)와 ProcessStop(2)을 같이 받는다. keyword 0x10 은 WINEVENT_KEYWORD_PROCESS 다.
	//
	// Stop 은 이벤트로 내보내지 않는다. 서버 스키마에 종료 타입이 없다. 그런데도 구독하는 이유는
	// 진단이다. 이 저장소에는 세션과 프로바이더가 멀쩡한데 ProcessStop 만 올라오고 ProcessStart 는
	// 한 건도 오지 않은 실기기 이력이 있다(커밋 22a5983). 원인은 아직 확인되지 않았다.
	// 둘을 같이 세어 두면 "Start 0건 / Stop 다수" 라는 모양이 로그에 그대로 드러나므로,
	// 프로바이더가 안 붙은 것인지 Start 만 안 오는 그 현상이 재현된 것인지 바로 가릴 수 있다.
	{sensor: "process", spec: "Microsoft-Windows-Kernel-Process:0xff:1,2:0x10"},

	// TCP 연결 시도만 받는다. 송수신(10/11 과 그 IPv6 짝 26/27)까지 받으면 양이 감당이 안 된다.
	// keyword 0x30 은 KERNEL_NETWORK_KEYWORD_IPV4(0x10) + IPV6(0x20) 다.
	{sensor: "network", spec: "Microsoft-Windows-Kernel-Network:0xff:12,28:0x30"},

	// 파일은 새로 생긴 것만 받는다. CreateNewFile(30) 하나이고 keyword 는 CREATE_NEW_FILE(0x1000)
	// 단독으로 충분하다.
	//
	// 자동실행 경로에 파일이 놓이는 것을 잡는 게 목적이라(detector R4) 그 이상은 필요 없다.
	// Read(15)/QueryInformation(22)은 물론이고 Write(16)도 켜지 않는다. 평범한 기기에서 초당
	// 수천 건이라 다른 이벤트를 전부 밀어낸다.
	//
	// DeletePath(26)/RenamePath(27)은 일부러 뺐다. 이 둘은 경로를 FileName 이 아니라 FilePath 에
	// 싣는데 MapFile 은 FileName 만 읽는다. 켜 두면 이벤트가 올라와도 전부 조용히 버려진다.
	// 삭제와 이름 변경까지 보려면 MapFile 이 FilePath 도 읽게 고친 뒤에 켜야 한다.
	{sensor: "file", spec: "Microsoft-Windows-Kernel-File:0xff:30:0x1000"},

	// DNS 는 질의 완료(3008)만 받는다.
	//
	// 3006(질의 발신)과 둘 다 받으면 같은 질의가 이벤트 두 건이 되어 대시보드에서 질의 수가
	// 두 배로 보인다. 하나만 골라야 하는데 3008 을 고른 이유는 응답 IP(QueryResults)와
	// 상태(QueryStatus)가 여기에만 실려 오기 때문이다. detector 는 DNS 를 판정에 쓰지 않고
	// 이 이벤트는 조사 화면용인데, 조사에서 필요한 것은 "무엇을 물었나" 보다 "무엇으로 풀렸나" 다.
	// 3006 의 장점인 "응답을 못 받은 질의도 남는다" 도 크게 잃지 않는다. 실패한 질의는 3008 이
	// 실패 상태를 달고 올라오기 때문이다.
	//
	// keyword 를 적지 않는다. 이 프로바이더의 3006/3008 은 매니페스트 keyword 가 0 이라
	// MatchAnyKeyword 와 무관하게 세션에 기록된다. 그런 상태에서 값을 지어내 적어 두면 나중에
	// 그 값이 수집 조건인 것처럼 읽힌다. EVENT_ENABLE_PROPERTY_IGNORE_KEYWORD_0 을 켜면
	// keyword 0 인 이벤트가 통째로 막히므로 그것도 켜지 않는다(라이브러리 기본값이 꺼짐이다).
	{sensor: "dns", spec: "Microsoft-Windows-DNS-Client:0xff:3008"},
}

// pktMonProvider 는 패킷 캡처용 프로바이더다. 위 목록과 달리 따로 두는 이유가 두 가지다.
//
// 첫째, 켤 조건이 다르다. 나머지는 센서 스위치만 보면 되지만 이것은 pktmon 캡처가 실제로
// 열렸을 때만 켜야 한다. 드라이버가 안 돌면 프로바이더만 붙고 이벤트는 0건이라, 그 상태를
// 로그에서 "켰다" 로 보이게 두면 원인을 찾는 사람을 속인다.
//
// 둘째, 이름을 코드로 만든다. keyword 0x10 을 손으로 적어 두면 그 숫자가 무엇인지 아는
// 곳(pktmon.go)과 쓰는 곳이 갈라진다.
//
// **같은 세션에 넣는다.** 별도 세션도 되지만 그러면 버퍼 풀과 플러시 주기가 따로 놀아
// 연결 이벤트와 패킷의 도착 순서가 더 흔들린다. 프로세스 귀속이 그 순서에 달려 있어서
// 순서가 덜 흔들리는 쪽이 낫다. 타임스탬프 기준계가 하나로 통일되는 것도 같은 이유다.
const sensorL7 = "l7"

// ETWSensor 는 ETW 실시간 세션에서 프로세스/네트워크/파일 이벤트를 받는다.
type ETWSensor struct {
	Factory    event.Factory
	WatchPaths []string
	// Sensors 는 서버가 내려준 센서 스위치다. nil 이면 전부 켠다.
	Sensors map[string]bool
	// Logger 가 비면 slog.Default() 를 쓴다.
	Logger *slog.Logger

	// PktMon 이 있으면 패킷 캡처 프로바이더를 같은 세션에 붙이고 프레임을 이쪽으로 넘긴다.
	// nil 이면 캡처를 못 열었다는 뜻이라 프로바이더도 켜지 않는다.
	PktMon *PktMonCapture
	// Flows 가 있으면 연결 이벤트가 알려 준 프로세스를 여기에 기억해 둔다.
	// L7Sensor 가 같은 것을 들고 있다가 SNI 에 이어 붙인다.
	Flows *FlowOwners

	// ProcessStart 와 ProcessStop 을 따로 센다. 둘의 비율이 진단 근거다(위 프로바이더 주석 참고).
	starts atomic.Uint64
	stops  atomic.Uint64
}

// Name 은 센서 이름이다.
func (s *ETWSensor) Name() string { return "etw" }

func (s *ETWSensor) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

// etwHealthInterval 은 수집 상태를 로그로 남기는 주기다.
const etwHealthInterval = time.Minute

// Run 은 ETW 세션을 열고 ctx 가 끝날 때까지 이벤트를 흘려보낸다.
//
// 세션을 못 열면 오류로 올린다. 관리자 권한이 없으면 StartTrace 가 거부되는데, 그걸 삼키면
// 수집이 조용히 0건이 되어 원인을 찾는 데 한참 걸린다. 이 프로젝트가 실제로 겪은 일이다.
func (s *ETWSensor) Run(ctx context.Context, out chan<- event.Event) error {
	session := etw.NewRealTimeSession(etwSessionName)
	if err := session.Start(); err != nil {
		return fmt.Errorf("ETW 세션(%s)을 열지 못했다. %s: %w", etwSessionName, sessionErrorHint(err, etwSessionName), err)
	}
	defer session.Stop()

	guids, err := s.enableProviders(session)
	if err != nil {
		return err
	}
	if len(guids) == 0 {
		return errors.New("켜진 ETW 프로바이더가 없다. 서버가 내려준 sensors 설정을 확인해라")
	}
	s.logger().Info("ETW 세션 시작", "session", etwSessionName, "providers", sortedKeys(guids))

	// 캡처는 세션이 끝나면 같이 끝내야 한다. 안 그러면 L7 센서가 오지 않을 프레임을 계속
	// 기다리고, 밖에서는 그게 "조용히 0건" 으로 보인다.
	if s.PktMon != nil {
		defer s.PktMon.Close()
	}

	consumer := etw.NewRealTimeConsumer(ctx)
	consumer.FromSessions(session)
	s.hookCallbacks(consumer, guids)
	if err := consumer.Start(); err != nil {
		return fmt.Errorf("ETW 트레이스를 열지 못했다: %w", err)
	}

	// 트레이스 처리는 별도 고루틴에서 돌기 때문에, 세션이 밖에서 멈추면(logman stop 등)
	// 에이전트는 멀쩡히 살아 있는데 이벤트만 0건이 된다. 그 상태를 알아채려고 끝을 지켜본다.
	traceEnded := make(chan struct{})
	go func() {
		consumer.Wait()
		close(traceEnded)
	}()

	traceDied := s.forward(ctx, consumer, traceEnded, guids, out)
	consumer.Stop()

	if traceDied {
		if err := consumer.Err(); err != nil {
			return fmt.Errorf("ETW 트레이스가 끝났다: %w", err)
		}
		return fmt.Errorf("ETW 트레이스가 예기치 않게 끝났다. 세션(%s)이 밖에서 멈췄을 수 있다", etwSessionName)
	}
	return ctx.Err()
}

// enableProviders 는 켜진 센서에 해당하는 프로바이더만 활성화하고 센서별 GUID 를 돌려준다.
//
// 돌려주는 GUID 는 라이브러리가 프로바이더 이름을 풀어 준 값이다. 들어오는 이벤트를 가릴 때
// 이 값을 쓰면 켠 것과 견주는 것이 같음이 보장된다.
//
// 하나라도 실패하면 오류로 올린다. 반쪽만 도는 상태는 0건보다 알아채기 어렵다.
func (s *ETWSensor) enableProviders(session *etw.RealTimeSession) (map[string]string, error) {
	guids := make(map[string]string, len(etwProviders))
	for _, p := range etwProviders {
		if !s.sensorEnabled(p.sensor) {
			continue
		}
		provider, err := etw.ParseProvider(p.spec)
		if err != nil {
			return nil, fmt.Errorf("%s 프로바이더를 찾지 못했다(%s): %w", p.sensor, p.spec, err)
		}
		if err := session.EnableProvider(provider); err != nil {
			return nil, fmt.Errorf("%s 프로바이더를 켜지 못했다(%s): %w", p.sensor, p.spec, err)
		}
		guids[p.sensor] = provider.GUID
	}

	// 패킷 캡처 프로바이더는 캡처가 실제로 열렸을 때만 켠다.
	if s.PktMon != nil {
		spec := pktMonProviderSpec()
		provider, err := etw.ParseProvider(spec)
		if err != nil {
			return nil, fmt.Errorf("pktmon 프로바이더를 찾지 못했다(%s): %w", spec, err)
		}
		if err := session.EnableProvider(provider); err != nil {
			return nil, fmt.Errorf("pktmon 프로바이더를 켜지 못했다(%s): %w", spec, err)
		}
		guids[sensorL7] = provider.GUID
	}
	return guids, nil
}

// hookCallbacks 는 소비자에 우리 처리를 끼워 넣는다.
//
// 둘 다 ETW 콜백 스레드에서 도는 자리를 고른 것이 핵심이다. 프레임은 EventRecordCallback 에서,
// 연결 기억은 EventCallback 에서 받는데 이 둘은 같은 스레드에서 배달 순서 그대로 불린다.
// 만약 연결 기억을 forward 고루틴(즉 consumer.Events 를 읽는 쪽)에서 했다면, ETW 가 순서를
// 지켜 보내 줘도 우리 고루틴 둘이 그 순서를 다시 흐트러뜨린다. 프로세스 귀속이 순서에
// 달려 있어서 그 한 겹은 우리가 없앨 수 있는 만큼 없애 둔다.
func (s *ETWSensor) hookCallbacks(consumer *etw.Consumer, guids map[string]string) {
	if s.PktMon != nil {
		consumer.EventRecordCallback = func(er *etw.EventRecord) bool {
			return s.handleRecord(er, guids[sensorL7])
		}
	}
	if s.Flows != nil {
		forward := consumer.EventCallback
		consumer.EventCallback = func(e *etw.Event) error {
			s.rememberFlow(e, guids["network"])
			return forward(e)
		}
	}
}

// handleRecord 는 원시 이벤트를 먼저 본다. 패킷 이벤트면 여기서 처리하고 끝낸다.
//
// 라이브러리의 일반 경로를 태우지 않는 이유는 프레임 바이트 때문이다. 그 경로는 TDH 로
// 모든 속성을 문자열로 렌더링하는데, 2KB 짜리 이진 페이로드를 패킷마다 문자열로 만드는 것은
// 비싸고 그 문자열 형식이 문서로 보장되지도 않는다. 원본 바이트를 그대로 읽는 편이 싸고 확실하다.
func (s *ETWSensor) handleRecord(er *etw.EventRecord, pktMonGUID string) bool {
	if er == nil || er.EventHeader.EventDescriptor.Id != eventPktMonPacket {
		return true
	}
	if !sameGUID(er.EventHeader.ProviderId.String(), pktMonGUID) {
		return true
	}
	if er.UserData != 0 && er.UserDataLength > 0 {
		s.PktMon.deliver(copyEventUserData(er.UserData, int(er.UserDataLength)))
	}
	// false 는 "이 이벤트는 더 처리하지 마라" 다.
	return false
}

// copyEventUserData 는 ETW 이벤트의 원시 payload 를 Go 슬라이스로 복사해 온다.
//
// 이 패키지에서 커널이 준 생주소를 다루는 곳은 여기 하나다. 불가피한 unsafe 는 한 곳에
// 가두고 근거를 남긴다.
//
// # 이 주소가 무엇인가
//
// addr 은 ETW 가 트레이스 콜백에 넘겨준 EVENT_RECORD.UserData 다. 커널이 잡아 둔 트레이스
// 버퍼 안을 가리키며 **Go 힙이 아니다.** 그래서 GC 가 이 대상을 옮기거나 회수하지 않는다.
// uintptr 을 포인터로 쓸 때 위험한 것은 "GC 가 그 사이 대상을 옮겨 주소가 낡는 것" 인데,
// Go 가 관리하지 않는 메모리라 그 일이 일어날 수 없다.
//
// # 왜 곧바로 복사하는가
//
// 대신 다른 수명 문제가 있다. 이 버퍼는 **콜백이 돌아가면 ETW 가 재사용한다.** 주소를 들고
// 있다가 나중에 읽으면 그때는 다른 패킷의 바이트가 들어 있다. 오류가 아니라 조용히 틀린
// 값이라 제일 나쁜 종류다. 그래서 콜백 안에서 바로 복사하고, 채널로는 복사본만 내보낸다.
//
// # 왜 unsafe.Pointer 로 바꾸지 않는가
//
// 라이브러리가 UserData 를 uintptr 로만 노출하고 안전한 접근자가 없어서, 슬라이스를 뜨려면
// 변환이 필요하다. 그런데 그 변환은 위 근거와 무관하게 go vet 의 unsafeptr 검사에 걸린다.
// **함수로 빼도 걸린다. 그 검사는 변환 표현 자체를 보기 때문이다**(확인함). 상시 경고를 하나
// 남겨 두면 다음 사람이 vet 출력을 통째로 흘려보게 되고, 그러면 진짜 문제가 생겨도 안 보인다.
// Windows 코드는 실행으로 검증할 수 없어서 vet 이 몇 안 되는 자동 안전망이다.
//
// 그래서 변환을 없앴다. 주소를 포인터로 바꾸는 대신 **주소를 인자로 받는 RtlMoveMemory**
// (kernel32 가 내보내는 memmove)로 복사한다. 검사를 우회하는 표현을 쓰지 않았다는 것이
// 중요하다. 그런 표현은 경고만 지우고 근거는 감춘다. 하는 일은 memmove 하나이고, 옮기는
// 바이트는 어차피 복사해야 하는 것이라 추가 비용은 호출 한 번뿐이다.
func copyEventUserData(addr uintptr, n int) []byte {
	buf := make([]byte, n)
	procRtlMoveMemory.Call(uintptr(unsafe.Pointer(&buf[0])), addr, uintptr(n))
	// 복사가 끝날 때까지 목적지가 살아 있어야 한다. 인자로 넘긴 uintptr 만으로는
	// 컴파일러가 buf 를 살아 있다고 보지 않는다.
	runtime.KeepAlive(buf)
	return buf
}

// rememberFlow 는 연결 이벤트가 알려 준 프로세스를 캐시에 넣는다.
//
// 시각은 이벤트에 실려 온 것이 아니라 지금 시각을 쓴다. 만료를 재는 쪽(Lookup)이 time.Now 를
// 보기 때문이다. 두 시계를 섞으면 어느 한쪽이 조금만 어긋나도 항목이 태어나자마자 만료되거나
// 만료돼야 할 것이 남는데, 그 어긋남은 실기기에서만 드러난다.
func (s *ETWSensor) rememberFlow(raw *etw.Event, networkGUID string) {
	if raw == nil {
		return
	}
	if id := raw.System.EventID; id != eventTCPConnectV4 && id != eventTCPConnectV6 {
		return
	}
	if !sameGUID(raw.System.Provider.Guid, networkGUID) {
		return
	}
	RememberNetworkFlow(s.Flows, properties(raw), procInfo, time.Now())
}

// sensorEnabled 는 그 센서를 켤지 본다. 설정을 아직 못 받았으면 전부 켠다.
func (s *ETWSensor) sensorEnabled(name string) bool {
	if s.Sensors == nil {
		return true
	}
	return s.Sensors[name]
}

// forward 는 소비자 채널에서 이벤트를 꺼내 변환하고 out 으로 보낸다.
// ctx 가 끝나거나 트레이스가 먼저 끝나면 돌아온다. 트레이스가 먼저 끝났으면 true 를 준다.
func (s *ETWSensor) forward(ctx context.Context, consumer *etw.Consumer, traceEnded <-chan struct{}, guids map[string]string, out chan<- event.Event) bool {
	health := time.NewTicker(etwHealthInterval)
	defer health.Stop()

	for {
		select {
		case <-ctx.Done():
			return false
		case <-traceEnded:
			return true
		case <-health.C:
			s.reportHealth()
		case raw, ok := <-consumer.Events:
			if !ok {
				return true
			}
			e, keep := s.convert(raw, guids)
			if !keep {
				continue
			}
			select {
			case out <- e:
			case <-ctx.Done():
				return false
			}
		}
	}
}

// convert 는 ETW 이벤트 하나를 서버로 보낼 이벤트로 바꾼다.
// 프로바이더와 이벤트 ID 로 갈라 etw_map.go 의 순수 함수에 넘긴다.
func (s *ETWSensor) convert(raw *etw.Event, guids map[string]string) (event.Event, bool) {
	at := raw.System.TimeCreated.SystemTime
	if at.IsZero() {
		at = time.Now()
	}
	guid := raw.System.Provider.Guid
	id := raw.System.EventID

	// 프로바이더를 먼저 가린 뒤 이벤트 ID 를 본다. 세 프로바이더가 같은 번호를 쓰기 때문에
	// (예: 10 은 Kernel-Network 에서 송신, Kernel-File 에서 NameCreate 다) 순서가 뒤집히면
	// 파일 이벤트를 네트워크로 읽는 것 같은 사고가 난다.
	switch {
	case sameGUID(guid, guids["process"]):
		switch id {
		case eventProcessStart:
			s.starts.Add(1)
			props := properties(raw)
			s.enrichProcess(props)
			return MapProcess(s.Factory, at, props, procInfo)
		case eventProcessStop:
			// 종료는 이벤트로 내보내지 않는다. 서버 스키마에 해당 타입이 없다. 세기만 한다.
			s.stops.Add(1)
		}

	case sameGUID(guid, guids["network"]):
		if id == eventTCPConnectV4 || id == eventTCPConnectV6 {
			return MapNetwork(s.Factory, at, properties(raw), procInfo)
		}

	case sameGUID(guid, guids["file"]):
		if id == eventCreateNewFile {
			return MapFile(s.Factory, at, properties(raw), s.WatchPaths)
		}

	case sameGUID(guid, guids["dns"]):
		if id == eventDNSQueryCompleted {
			// PID 는 헤더에서 꺼낸다. 3006/3008 payload 에는 PID 가 없다.
			// ClientPID 속성은 3010/3011/3020 의 v1 이상에만 있고, 그 이벤트들은 캐시 조회라
			// 우리가 받는 질의 완료와 짝이 맞지 않는다.
			//
			// 헤더 PID 를 클라이언트 PID 로 보는 것은 이 이벤트를 dnsapi.dll 이 질의를 낸
			// 프로세스 안에서 기록하기 때문이다. 다만 1차 문서로 확인한 사실이 아니다.
			// 실기기에서 브라우저로 접속해 보고 process 가 그 브라우저로 나오는지,
			// 아니면 전부 svchost.exe(dnscache 서비스)로 나오는지 확인해야 한다.
			// 후자라면 이 프로바이더로는 프로세스를 알 수 없다는 뜻이다.
			return MapDNS(s.Factory, at, properties(raw), int(raw.System.Execution.ProcessID), procInfo)
		}
	}
	return event.Event{}, false
}

// sortedKeys 는 로그에 찍을 때 순서가 흔들리지 않게 키를 정렬해 준다.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// enrichProcess 는 ETW 가 주지 못하는 두 값을 프로세스를 직접 조회해 채운다.
//
// ProcessStart 의 ImageName 은 파일명까지만이고 명령행은 아예 없다(etw_map.go 위쪽 주석 참고).
// 갓 뜬 프로세스라 아직 살아 있을 확률이 높지만, 순식간에 끝나는 프로세스는 조회에 실패한다.
// 실패하면 채우지 않고 넘어간다. MapProcess 가 ImageName 으로 물러나 이벤트는 그대로 나간다.
func (s *ETWSensor) enrichProcess(props map[string]string) {
	pid, ok := parsePID(prop(props, "ProcessID"))
	if !ok {
		return
	}
	if path := procInfo.Name(pid); path != "" {
		props[propImagePath] = path
	}
	// 명령행은 프로세스당 한 번만 필요하므로 캐시를 씌우지 않는다.
	if cmdline := liveProc.Cmdline(pid); cmdline != "" {
		props[propCommandLine] = cmdline
	}
}

// reportHealth 는 지금까지 받은 프로세스 이벤트 수를 남긴다.
//
// Start 는 0 인데 Stop 만 쌓이는 모양이 이 프로젝트에서 실제로 났던 고장이다(커밋 22a5983).
// 그때는 왜 0건인지 알 방법이 없어 한참 헤맸다. 그 모양을 로그에서 바로 알아보게 한다.
func (s *ETWSensor) reportHealth() {
	starts, stops := s.starts.Load(), s.stops.Load()
	if starts == 0 && stops > 0 {
		s.logger().Warn("ProcessStop 만 올라오고 ProcessStart 가 한 건도 없다. "+
			"프로바이더는 붙었으나 시작 이벤트가 오지 않는 상태다",
			"stops", stops, "session", etwSessionName)
		return
	}
	s.logger().Info("ETW 수집 상태", "processStart", starts, "processStop", stops)

	if s.PktMon != nil {
		s.PktMon.ReportHealth()
	}
	if s.Flows != nil {
		// 이 비율이 Windows 쪽 프로세스 귀속이 실제로 먹는지를 말해 준다. 낮으면 연결
		// 이벤트가 안 오는 것인지 도착 순서가 뒤집힌 것인지 따로 파야 한다.
		hits, misses := s.Flows.Stats()
		s.logger().Info("SNI 프로세스 귀속 상태", "hit", hits, "miss", misses, "cached", s.Flows.Size())
	}
}

// properties 는 파싱된 속성을 문자열 맵 하나로 모은다.
// golang-etw 는 템플릿 종류에 따라 EventData 나 UserData 중 한쪽에 넣으므로 둘 다 본다.
func properties(raw *etw.Event) map[string]string {
	props := make(map[string]string, len(raw.EventData)+len(raw.UserData))
	sections := []map[string]interface{}{raw.UserData, raw.EventData}
	for _, section := range sections {
		for k, v := range section {
			if s, ok := v.(string); ok {
				props[k] = s
				continue
			}
			props[k] = fmt.Sprint(v)
		}
	}
	return props
}

// sameGUID 는 중괄호와 대소문자를 무시하고 GUID 를 견준다.
//
// 빈 값은 어떤 것과도 같지 않다. 꺼진 센서의 GUID 는 빈 문자열인데, 그것을 같다고 보면
// GUID 를 못 읽은 이벤트가 꺼 둔 센서의 것으로 둔갑한다.
func sameGUID(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return strings.EqualFold(strings.Trim(a, "{}"), strings.Trim(b, "{}"))
}

// liveProcess 는 살아 있는 프로세스에서 이미지 경로와 명령행을 읽는다.
// ETW 가 PID 만 주기 때문에 필요하다. 이 조회들은 실패해도 오류를 올리지 않고 빈 값을 준다.
// 프로세스는 언제든 먼저 죽을 수 있고, 그 때문에 이벤트를 통째로 버리는 게 더 손해다.
type liveProcess struct{}

// liveProc 는 실제 조회를 하는 구현이다. 상태가 없어 하나만 둔다.
var liveProc liveProcess

// procInfo 는 이미지 경로 조회에 캐시를 씌운 것이다. 네트워크 이벤트마다 불리므로 캐시가 필요하다.
var procInfo = &pidCache{lookup: liveProc.Name}

// Name 은 PID 의 전체 실행 경로를 준다. ProcessNamer 를 만족한다.
func (liveProcess) Name(pid int) string {
	handle, err := openForQuery(pid)
	if err != nil {
		return ""
	}
	defer syscall.CloseHandle(handle)

	buf := make([]uint16, syscall.MAX_LONG_PATH)
	size := uint32(len(buf))
	ret, _, _ := procQueryFullProcessImageNameW.Call(
		uintptr(handle), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if ret == 0 || size == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf[:size])
}

// Cmdline 은 PID 의 명령행을 준다.
//
// PEB 를 직접 읽는 대신 NtQueryInformationProcess 의 ProcessCommandLineInformation 을 쓴다.
// Windows 8.1 부터 있고, 다른 프로세스 메모리를 따라다니지 않아 훨씬 단순하다.
// 결과는 버퍼 앞에 놓인 UNICODE_STRING 이 가리킨다.
func (liveProcess) Cmdline(pid int) string {
	handle, err := openForQuery(pid)
	if err != nil {
		return ""
	}
	defer syscall.CloseHandle(handle)

	buf := make([]byte, 4096)
	for attempt := 0; attempt < 2; attempt++ {
		var needed uint32
		status, _, _ := procNtQueryInformationProcess.Call(
			uintptr(handle),
			processCommandLineInformation,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(&needed)))

		switch {
		case status == 0:
			us := (*unicodeString)(unsafe.Pointer(&buf[0]))
			if us.Buffer == nil || us.Length == 0 {
				return ""
			}
			cmdline := syscall.UTF16ToString(unsafe.Slice(us.Buffer, int(us.Length)/2))
			runtime.KeepAlive(buf)
			return cmdline
		case status == statusInfoLengthMismatch && needed > uint32(len(buf)) && needed <= maxCmdlineBytes:
			buf = make([]byte, needed)
		default:
			return ""
		}
	}
	return ""
}

// openForQuery 는 정보 조회용으로만 프로세스를 연다.
// PROCESS_QUERY_LIMITED_INFORMATION 이면 충분하고, 보호된 프로세스도 열리는 경우가 많다.
func openForQuery(pid int) (syscall.Handle, error) {
	const queryLimitedInformation = 0x1000
	return syscall.OpenProcess(queryLimitedInformation, false, uint32(pid))
}

const (
	// ProcessCommandLineInformation. NtQueryInformationProcess 의 정보 클래스 번호다.
	processCommandLineInformation = 60
	statusInfoLengthMismatch      = 0xC0000004
	// 명령행이 이보다 크면 정상적인 값이 아니라고 보고 포기한다.
	maxCmdlineBytes = 64 * 1024
)

// unicodeString 은 Win32 UNICODE_STRING 이다.
type unicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

var (
	kernel32                       = syscall.NewLazyDLL("kernel32.dll")
	ntdll                          = syscall.NewLazyDLL("ntdll.dll")
	procQueryFullProcessImageNameW = kernel32.NewProc("QueryFullProcessImageNameW")
	// RtlMoveMemory 는 kernel32 가 내보내는 memmove 다. copyEventUserData 가 쓴다.
	procRtlMoveMemory             = kernel32.NewProc("RtlMoveMemory")
	procNtQueryInformationProcess = ntdll.NewProc("NtQueryInformationProcess")
)
