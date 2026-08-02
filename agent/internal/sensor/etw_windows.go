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
// 커널 로거("NT Kernel Logger")로 바꾸지 마라. 시스템에 하나뿐이라 다른 도구와 부딪혀 0건이 된다.
const etwSessionName = "EDRdog-Agent"

// 프로바이더 GUID 는 적어 두지 않는다. 켤 때 라이브러리가 풀어 준 값을 들고 있다가 쓴다.
// 손으로 적으면 켤 때 쓰는 이름과 견줄 때 쓰는 GUID 가 어긋나도 오류 없이 조용히 0건이 된다.

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
// spec 형식은 이름:EnableLevel:이벤트ID들:MatchAnyKeyword:MatchAllKeyword 다.
// 이벤트 ID 를 빼면 커널 필터가 풀려 콜백까지 올라오는 양이 통째로 늘어난다.
type etwProvider struct {
	sensor string
	spec   string
}

var etwProviders = []etwProvider{
	// Stop(2)은 내보내지 않지만 빼지 마라. "Start 0건 / Stop 다수" 모양이 유일한 진단 근거다.
	{sensor: "process", spec: "Microsoft-Windows-Kernel-Process:0xff:1,2:0x10"},

	// 연결 시도(12,28)만 받는다. 송수신(10/11, 26/27)까지 켜면 양이 감당이 안 된다.
	{sensor: "network", spec: "Microsoft-Windows-Kernel-Network:0xff:12,28:0x30"},

	// Write(16)를 켜면 초당 수천 건이 다른 이벤트를 밀어낸다.
	// DeletePath(26)/RenamePath(27)은 경로를 FilePath 에 실어, 켜도 MapFile 이 전부 조용히 버린다.
	{sensor: "file", spec: "Microsoft-Windows-Kernel-File:0xff:30:0x1000"},

	// 3006 까지 받으면 같은 질의가 두 건이 된다. 3008 에만 응답 IP 와 상태가 실려 온다.
	// keyword 를 적지 마라. 이 이벤트는 매니페스트 keyword 가 0 이라 적으면 조건인 것처럼 읽힌다.
	{sensor: "dns", spec: "Microsoft-Windows-DNS-Client:0xff:3008"},
}

// sensorL7 은 패킷 캡처 프로바이더의 센서 이름이다. 캡처가 열렸을 때만 켠다.
// 별도 세션으로 떼지 마라. 버퍼 풀이 갈라지면 연결 이벤트와 패킷의 도착 순서가 더 흔들린다.
const sensorL7 = "l7"

// ETWSensor 는 ETW 실시간 세션에서 프로세스/네트워크/파일 이벤트를 받는다.
type ETWSensor struct {
	Factory    event.Factory
	WatchPaths []string
	// Sensors 는 서버가 내려준 센서 스위치다. nil 이면 전부 켠다.
	Sensors map[string]bool
	// Logger 가 비면 slog.Default() 를 쓴다.
	Logger *slog.Logger
	// Hasher 가 있으면 프로세스 이벤트에 실행 이미지의 sha256 을 붙인다. nil 이면 붙이지 않는다.
	Hasher *FileHasher

	// PktMon 이 있으면 패킷 캡처 프로바이더를 같은 세션에 붙이고 프레임을 이쪽으로 넘긴다.
	// nil 이면 캡처를 못 열었다는 뜻이라 프로바이더도 켜지 않는다.
	PktMon *PktMonCapture
	// Flows 가 있으면 연결 이벤트가 알려 준 프로세스를 여기에 기억해 둔다.
	// L7Sensor 가 같은 것을 들고 있다가 SNI 에 이어 붙인다.
	Flows *FlowOwners

	// ProcessStart 와 ProcessStop 을 따로 센다. 둘의 비율이 진단 근거다.
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
// 세션 실패를 삼키면 안 된다. 관리자 권한이 없을 때 수집이 조용히 0건이 된다.
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

	// 캡처는 세션이 끝나면 같이 끝낸다. 안 그러면 L7 센서가 오지 않을 프레임을 계속 기다린다.
	if s.PktMon != nil {
		defer s.PktMon.Close()
	}

	consumer := etw.NewRealTimeConsumer(ctx)
	consumer.FromSessions(session)
	s.hookCallbacks(consumer, guids)
	if err := consumer.Start(); err != nil {
		return fmt.Errorf("ETW 트레이스를 열지 못했다: %w", err)
	}

	// 이 감시를 빼면 세션이 밖에서 멈춰도(logman stop 등) 에이전트만 살아 이벤트가 0건이 된다.
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
// 하나라도 실패하면 멈춘다. 반쪽만 도는 상태는 0건보다 알아채기 어렵다.
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
// 둘 다 ETW 콜백 스레드여야 한다. forward 고루틴으로 옮기면 배달 순서가 다시 흐트러져
// SNI 에 프로세스가 안 붙는다.
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
// 라이브러리 일반 경로로 넘기면 2KB 이진 페이로드를 패킷마다 TDH 로 문자열 렌더링하게 된다.
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
// 콜백이 돌아가면 ETW 가 이 버퍼를 재사용한다. 나중에 읽으면 다른 패킷의 바이트가 들어 있다.
// RtlMoveMemory 를 unsafe.Pointer 변환으로 바꾸지 마라. go vet 의 unsafeptr 이 상시 경고를 낸다.
func copyEventUserData(addr uintptr, n int) []byte {
	buf := make([]byte, n)
	procRtlMoveMemory.Call(uintptr(unsafe.Pointer(&buf[0])), addr, uintptr(n))
	// 복사가 끝날 때까지 목적지가 살아 있어야 한다.
	runtime.KeepAlive(buf)
	return buf
}

// rememberFlow 는 연결 이벤트가 알려 준 프로세스를 캐시에 넣는다.
// 이벤트 시각으로 바꾸지 마라. 만료를 재는 Lookup 은 time.Now 를 봐서 두 시계가 섞인다.
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

	// 프로바이더가 먼저다. 순서를 뒤집으면 번호가 겹쳐(10 = 네트워크 송신 / 파일 NameCreate)
	// 파일 이벤트를 네트워크로 읽는다.
	switch {
	case sameGUID(guid, guids["process"]):
		switch id {
		case eventProcessStart:
			s.starts.Add(1)
			props := properties(raw)
			s.enrichProcess(props)
			return MapProcess(s.Factory, at, props, procInfo, s.Hasher)
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

// enrichProcess 는 ETW 가 주지 못하는 전체 경로와 명령행을 프로세스를 직접 조회해 채운다.
// 실패해도 오류로 올리지 않는다. 순식간에 끝난 프로세스 때문에 실행 사실을 잃으면 안 된다.
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
// 이 로그가 없으면 실기기에서 왜 0건인지 알 방법이 없다. 실제로 한 번 그래서 한참 헤맸다.
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
	if s.Hasher != nil {
		h := s.Hasher.Stats()
		s.logger().Info("실행 파일 해시 상태",
			"hashed", h.Hashed, "cached", h.Cached, "failed", h.Failed, "tooBig", h.TooBig)
	}
	if s.Flows != nil {
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
// 빈 값을 같다고 보면 GUID 를 못 읽은 이벤트가 꺼 둔 센서의 것으로 둔갑한다.
func sameGUID(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return strings.EqualFold(strings.Trim(a, "{}"), strings.Trim(b, "{}"))
}

// liveProcess 는 살아 있는 프로세스에서 이미지 경로와 명령행을 읽는다.
// 실패를 오류로 올리면 언제든 먼저 죽는 프로세스 때문에 이벤트를 통째로 버리게 된다.
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

// Cmdline 은 PID 의 명령행을 준다. PEB 대신 ProcessCommandLineInformation 을 쓴다.
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
// 권한을 넓히면 보호된 프로세스가 안 열려 조회 실패가 늘어난다.
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
