// Package event 는 센서가 관찰한 것을 서버로 보낼 형식으로 담는다.
//
// 형식은 detector 가 판정 입력으로 쓰는 스키마와 같다(docs/agent-protocol.md).
// 예전에는 osquery 의 result-log 를 흉내내느라 값이 columns 안에 한 겹 들어가 있었고
// 서버가 그 껍데기를 벗겼는데, 이제 양쪽을 다 우리가 만드니 중간 변환을 두지 않는다.
package event

import (
	"encoding/json"
	"time"
)

// 이벤트 종류. detector 의 Event.TYPE_* 와 같은 문자열이어야 한다.
const (
	TypeProcess = "process"
	TypeNetwork = "network"
	TypeFile    = "file"
	TypeScript  = "script"
	TypeDNS     = "dns"
	TypeL7      = "l7"
)

// 파일 동작. detail 의 action 에 담긴다.
//
// 상수로 두는 이유는 센서가 넷이나 되기 때문이다. 각자 문자열 리터럴을 적으면 한 곳에서
// "create" 로 쓰는 순간 대시보드 집계가 CREATE 와 create 둘로 갈리고, 그건 오류 없이 조용히
// 틀린다. 대문자로 맞춘 것은 서버 쪽 다른 열거값 표기와 같은 모양이기 때문이다.
const (
	FileActionCreate = "CREATE"
	FileActionWrite  = "WRITE"
	FileActionRename = "RENAME"
	FileActionDelete = "DELETE"
)

// 전송 계층 이름. detail 의 protocol 에 담긴다.
// 소문자인 이유는 packet.Flow.Protocol 이 이미 소문자로 주기 때문이다. 한쪽을 대문자로 바꾸면
// 그 변환을 잊은 자리에서 값이 갈린다.
const (
	ProtocolTCP = "tcp"
	ProtocolUDP = "udp"
)

// Event 는 서버로 보내는 이벤트 한 건이다.
//
// tenantId 는 없다. 서버가 node_key 로 풀어 심는다. 엔드포인트가 보낸 조직 태그를 믿으면
// 다른 조직 데이터에 섞어 넣을 수 있다.
type Event struct {
	Host    string `json:"host"`
	Type    string `json:"type"`
	TS      int64  `json:"ts"` // epoch millis
	Process string `json:"process"`
	Parent  string `json:"parent,omitempty"`
	Cmdline string `json:"cmdline,omitempty"`

	DestIP   string `json:"destIp,omitempty"`
	DestPort int    `json:"destPort,omitempty"`

	// SHA256 은 실행 파일 내용의 해시다. 소문자 16진수 64자이고 모르면 비운다.
	//
	// Detail 에 묻지 않고 별도 필드로 두는 이유는 Domain 과 같다. 알려진 악성코드 해시 목록과
	// 맞춰 보는 조회 대상이라 컬럼이어야 한다. JSON 문자열 안에 있으면 조회를 걸 수 없다.
	SHA256 string `json:"sha256,omitempty"`

	// Domain 은 DNS 질의 이름 또는 TLS SNI 다. 검색 대상이라 별도 필드로 둔다.
	// Detail 안에 묻으면 대시보드에서 도메인으로 조회할 수 없다.
	Domain string `json:"domain,omitempty"`
	// Detail 은 타입별 부가정보를 담은 JSON 문자열이다. pid 와 ppid, 파일 동작, 전송 계층,
	// 질의 타입, 응답 IP 목록, 인증서 발급자와 지문 같은 것이 들어간다.
	//
	// 필드를 하나씩 늘리지 않고 JSON 한 칸으로 받는 이유는 이 값들이 판정에 쓰이지 않고
	// 조사 화면에서 보여줄 용도이기 때문이다. 인증서 항목이 늘 때마다 스키마를 고치고
	// 서비스 셋을 같이 배포하는 비용이 이득보다 크다.
	Detail string `json:"detail,omitempty"`
}

// Factory 는 호스트 이름을 쥐고 이벤트를 만든다.
// 센서가 필드를 직접 채우면 basename 을 빠뜨리거나 초 단위 시각을 넣는 실수가 나므로 생성을 여기로 모은다.
type Factory struct {
	Host string
}

// ProcessInfo 는 프로세스 실행 하나에 대해 센서가 관찰한 값이다.
//
// 위치 인자 대신 구조체를 받는 이유는 값이 늘었기 때문이다. path, cmdline, parent, sha256 이
// 전부 문자열이라 순서를 틀려도 컴파일이 통과하고, 그러면 cmdline 자리에 부모 이름이 들어간 채로
// 서버까지 올라간다. 이름을 적어 넘기면 그 사고가 아예 생기지 않는다.
type ProcessInfo struct {
	Path    string // 실행 파일 경로. 전체 경로를 알면 전체 경로
	Cmdline string
	Parent  string // 부모 프로세스 이름
	PID     int
	PPID    int
	SHA256  string // 실행 파일 해시. 못 구하면 빈 값
}

// FileInfo 는 파일 변경 하나에 대해 센서가 관찰한 값이다.
type FileInfo struct {
	Path   string
	Action string // FileAction* 상수. 모르면 빈 값
	SHA256 string // 파일 내용 해시. 완성된 파일임을 확신할 수 없으면 빈 값이어야 한다
}

// NetworkInfo 는 아웃바운드 연결 하나에 대해 센서가 관찰한 값이다.
type NetworkInfo struct {
	ProcessPath string // 연결을 만든 프로세스의 이미지 경로
	PID         int
	Protocol    string // Protocol* 상수
	DestIP      string
	DestPort    int
}

// DNSInfo 는 DNS 질의 하나에 대해 센서가 관찰한 값이다.
type DNSInfo struct {
	ProcessPath string // 질의를 낸 프로세스의 실행 경로. 알 수 없으면 빈 값
	PID         int
	Protocol    string // Protocol* 상수. DNS 는 보통 udp 지만 tcp 로도 나간다
	Domain      string
}

// L7Info 는 TLS 핸드셰이크 하나에서 뽑은 값이다.
//
// PID 가 없다. 이 이벤트의 프로세스는 소켓 주인을 되짚어 찾는 것이라 경로만 나오고 PID 는
// 남지 않는다. 채울 수 없는 필드를 만들어 두면 다음 사람이 "왜 늘 비어 있나" 를 묻게 된다.
type L7Info struct {
	ProcessPath string
	Protocol    string // Protocol* 상수
	Domain      string
	DestIP      string
	DestPort    int
}

// Process 는 프로세스 실행 이벤트를 만든다.
func (f Factory) Process(at time.Time, p ProcessInfo) Event {
	return f.exec(TypeProcess, at, p)
}

// Script 는 스크립트 인터프리터 실행 이벤트를 만든다.
// 컬럼 구조는 Process 와 같고 종류만 다르다. detector 가 script 에만 T1059 룰을 건다.
func (f Factory) Script(at time.Time, p ProcessInfo) Event {
	return f.exec(TypeScript, at, p)
}

func (f Factory) exec(eventType string, at time.Time, p ProcessInfo) Event {
	detail := make(map[string]any, 2)
	putInt(detail, "pid", p.PID)
	putInt(detail, "ppid", p.PPID)

	return Event{
		Host:    f.Host,
		Type:    eventType,
		TS:      millis(at),
		Process: basename(p.Path),
		Parent:  p.Parent,
		Cmdline: p.Cmdline,
		SHA256:  p.SHA256,
		Detail:  encodeDetail(detail),
	}
}

// Network 는 아웃바운드 연결 이벤트를 만든다.
// ProcessPath 는 연결을 만든 프로세스의 이미지 경로다. 이 값을 채우는 것이 자체 수집기의 존재 이유다.
// Zeek 는 패킷만 보므로 누가 연결했는지 알 수 없고, osquery 는 두 플랫폼 모두 실시간 소켓을 못 준다.
func (f Factory) Network(at time.Time, n NetworkInfo) Event {
	detail := make(map[string]any, 2)
	putInt(detail, "pid", n.PID)
	putString(detail, "protocol", n.Protocol)

	return Event{
		Host:     f.Host,
		Type:     TypeNetwork,
		TS:       millis(at),
		Process:  basename(n.ProcessPath),
		DestIP:   n.DestIP,
		DestPort: n.DestPort,
		Detail:   encodeDetail(detail),
	}
}

// File 은 파일 변경 이벤트를 만든다.
// detector 의 T1547 룰이 전체 경로에서 자동실행 표식을 찾으므로 cmdline 에 경로 전체를 담는다.
func (f Factory) File(at time.Time, fi FileInfo) Event {
	detail := make(map[string]any, 1)
	putString(detail, "action", fi.Action)

	return Event{
		Host:    f.Host,
		Type:    TypeFile,
		TS:      millis(at),
		Process: basename(fi.Path),
		Cmdline: fi.Path,
		SHA256:  fi.SHA256,
		Detail:  encodeDetail(detail),
	}
}

// DNS 는 DNS 질의 이벤트를 만든다.
//
// ProcessPath 는 질의를 낸 프로세스의 실행 경로다. 알 수 없으면 비운다. Windows 는 ETW 가
// 프로세스를 알려주지만 패킷에서 뽑을 때는 누가 낸 질의인지 알 수 없다.
//
// detail 에는 질의 타입과 응답 IP 목록 같은 부가정보를 넣는다.
func (f Factory) DNS(at time.Time, d DNSInfo, detail map[string]any) Event {
	full := copyDetail(detail, 2)
	putInt(full, "pid", d.PID)
	putString(full, "protocol", d.Protocol)

	return Event{
		Host:    f.Host,
		Type:    TypeDNS,
		TS:      millis(at),
		Process: basename(d.ProcessPath),
		Domain:  d.Domain,
		Detail:  encodeDetail(full),
	}
}

// L7 은 TLS 핸드셰이크에서 뽑은 메타데이터 이벤트를 만든다.
//
// Domain 은 ClientHello 의 SNI 이고 인증서 정보는 detail 에 넣는다.
// 페이로드 자체는 절대 담지 않는다. 통신 내용을 서버로 보내는 것은 수집이 아니라 감청이다.
func (f Factory) L7(at time.Time, l L7Info, detail map[string]any) Event {
	full := copyDetail(detail, 1)
	putString(full, "protocol", l.Protocol)

	return Event{
		Host:     f.Host,
		Type:     TypeL7,
		TS:       millis(at),
		Process:  basename(l.ProcessPath),
		DestIP:   l.DestIP,
		DestPort: l.DestPort,
		Domain:   l.Domain,
		Detail:   encodeDetail(full),
	}
}

// putInt 는 관측한 값만 담는다.
//
// pid 0 은 "관측하지 못했다" 는 뜻이지 0번 프로세스가 아니다. 그대로 실어 보내면 ClickHouse 에
// 0 이 쌓여 진짜 pid 와 섞이고, 조사 화면에서 그 0 을 걸러 낼 방법이 없다.
func putInt(detail map[string]any, key string, value int) {
	if value > 0 {
		detail[key] = value
	}
}

// putString 은 빈 문자열이 아닌 값만 담는다. 이유는 putInt 와 같다.
func putString(detail map[string]any, key, value string) {
	if value != "" {
		detail[key] = value
	}
}

// copyDetail 은 센서가 준 부가정보를 복사한 새 맵을 만든다.
//
// 받은 맵을 그대로 고치지 않는 이유는 그 맵의 주인이 센서이기 때문이다. 센서가 맵을 재사용하면
// 팩토리가 넣은 키가 다음 이벤트에 딸려 나가는데, 그건 오류 없이 조용히 틀린다.
func copyDetail(detail map[string]any, extra int) map[string]any {
	full := make(map[string]any, len(detail)+extra)
	for k, v := range detail {
		full[k] = v
	}
	return full
}

// encodeDetail 은 부가정보를 JSON 문자열로 만든다.
//
// 직렬화에 실패해도 이벤트를 버리지 않고 부가정보만 비운다. 도메인과 프로세스라는 핵심은
// 이미 별도 필드에 있으므로, 곁가지 때문에 관측 사실 자체를 잃는 쪽이 나쁘다.
func encodeDetail(detail map[string]any) string {
	if len(detail) == 0 {
		return ""
	}
	raw, err := json.Marshal(detail)
	if err != nil {
		return ""
	}
	return string(raw)
}

func millis(at time.Time) int64 {
	return at.UnixMilli()
}

// basename 은 경로에서 파일명만 남긴다.
// 한 에이전트가 두 플랫폼을 다루므로 구분자를 둘 다 본다. ETW 는 전체 경로 없이 파일명만 주기도 한다.
func basename(path string) string {
	cut := -1
	for i := 0; i < len(path); i++ {
		if path[i] == '/' || path[i] == '\\' {
			cut = i
		}
	}
	return path[cut+1:]
}
