// Package event 는 센서가 관찰한 것을 서버로 보낼 형식으로 담는다.
// 형식은 detector 가 판정 입력으로 쓰는 스키마와 같다(docs/agent-protocol.md).
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
// 센서마다 리터럴을 적으면 한 곳만 "create" 로 써도 집계가 둘로 갈리고, 그건 조용히 틀린다.
const (
	FileActionCreate = "CREATE"
	FileActionWrite  = "WRITE"
	FileActionRename = "RENAME"
	FileActionDelete = "DELETE"
)

// 전송 계층 이름. detail 의 protocol 에 담긴다.
// packet.Flow.Protocol 이 소문자로 준다. 한쪽을 대문자로 바꾸면 변환을 잊은 자리에서 값이 갈린다.
const (
	ProtocolTCP = "tcp"
	ProtocolUDP = "udp"
)

// Event 는 서버로 보내는 이벤트 한 건이다.
//
// 서버 쪽 Java DTO 3벌과 손으로 맞춰 둔 스키마 계약이다(#182). 필드명, json 태그, 필드 순서를
// 바꾸면 서버가 조용히 못 읽는다.
//
// tenantId 를 필드로 넣으면 안 된다. 엔드포인트가 보낸 조직 태그를 믿는 순간 다른 조직 데이터에
// 섞어 넣을 수 있어 서버가 node_key 로 풀어 심는다.
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
	// Domain 과 같이 Detail 안으로 옮기면 조회를 걸 수 없어 컬럼으로 둔다.
	SHA256 string `json:"sha256,omitempty"`

	// Domain 은 DNS 질의 이름 또는 TLS SNI 다. 검색 대상이라 별도 필드로 둔다.
	Domain string `json:"domain,omitempty"`
	// Detail 은 타입별 부가정보를 담은 JSON 문자열이다. pid 와 ppid, 파일 동작, 전송 계층,
	// 질의 타입, 응답 IP 목록, 인증서 발급자와 지문 같은 것이 들어간다.
	Detail string `json:"detail,omitempty"`
}

// Factory 는 호스트 이름을 쥐고 이벤트를 만든다. 센서가 필드를 직접 채우지 않게 생성을 여기로 모은다.
type Factory struct {
	Host string
}

// ProcessInfo 는 프로세스 실행 하나에 대해 센서가 관찰한 값이다.
// 위치 인자로 되돌리면 전부 문자열이라 순서를 틀려도 컴파일이 통과한다.
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

// L7Info 는 TLS 핸드셰이크 하나에서 뽑은 값이다. 소켓 주인을 되짚어 찾는 것이라 PID 는 없다.
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
// ProcessPath 는 연결을 만든 프로세스의 이미지 경로다.
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
// ProcessPath 는 질의를 낸 프로세스의 실행 경로다. 알 수 없으면 비운다.
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
// Domain 은 ClientHello 의 SNI 이고 인증서 정보는 detail 에 넣는다. 페이로드 자체는 절대 담지 않는다.
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

// putInt 는 관측한 값만 담는다. pid 0 은 "관측하지 못했다" 는 뜻이지 0번 프로세스가 아니다.
// 그대로 실어 보내면 ClickHouse 에 0 이 쌓여 진짜 pid 와 섞이고 걸러 낼 방법이 없다.
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
// 복사를 빼고 받은 맵을 고치면, 센서가 맵을 재사용할 때 팩토리가 넣은 키가 다음 이벤트에 딸려 나간다.
func copyDetail(detail map[string]any, extra int) map[string]any {
	full := make(map[string]any, len(detail)+extra)
	for k, v := range detail {
		full[k] = v
	}
	return full
}

// encodeDetail 은 부가정보를 JSON 문자열로 만든다.
// 직렬화에 실패해도 이벤트를 버리지 않고 부가정보만 비운다. 곁가지 때문에 관측 사실을 잃으면 안 된다.
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
