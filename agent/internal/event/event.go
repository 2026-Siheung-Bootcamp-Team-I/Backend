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

	// Domain 은 DNS 질의 이름 또는 TLS SNI 다. 검색 대상이라 별도 필드로 둔다.
	// Detail 안에 묻으면 대시보드에서 도메인으로 조회할 수 없다.
	Domain string `json:"domain,omitempty"`
	// Detail 은 타입별 부가정보를 담은 JSON 문자열이다. 질의 타입, 응답 IP 목록,
	// 인증서 발급자와 지문 같은 것이 들어간다.
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

// Process 는 프로세스 실행 이벤트를 만든다. parent 는 부모 프로세스 이름이다.
func (f Factory) Process(at time.Time, path, cmdline, parent string) Event {
	return f.exec(TypeProcess, at, path, cmdline, parent)
}

// Script 는 스크립트 인터프리터 실행 이벤트를 만든다.
// 컬럼 구조는 Process 와 같고 종류만 다르다. detector 가 script 에만 T1059 룰을 건다.
func (f Factory) Script(at time.Time, path, cmdline, parent string) Event {
	return f.exec(TypeScript, at, path, cmdline, parent)
}

func (f Factory) exec(eventType string, at time.Time, path, cmdline, parent string) Event {
	return Event{
		Host:    f.Host,
		Type:    eventType,
		TS:      millis(at),
		Process: basename(path),
		Parent:  parent,
		Cmdline: cmdline,
	}
}

// Network 는 아웃바운드 연결 이벤트를 만든다.
// path 는 연결을 만든 프로세스의 이미지 경로다. 이 값을 채우는 것이 자체 수집기의 존재 이유다.
// Zeek 는 패킷만 보므로 누가 연결했는지 알 수 없고, osquery 는 두 플랫폼 모두 실시간 소켓을 못 준다.
func (f Factory) Network(at time.Time, path, destIP string, destPort int) Event {
	return Event{
		Host:     f.Host,
		Type:     TypeNetwork,
		TS:       millis(at),
		Process:  basename(path),
		DestIP:   destIP,
		DestPort: destPort,
	}
}

// File 은 파일 변경 이벤트를 만든다.
// detector 의 T1547 룰이 전체 경로에서 자동실행 표식을 찾으므로 cmdline 에 경로 전체를 담는다.
func (f Factory) File(at time.Time, targetPath string) Event {
	return Event{
		Host:    f.Host,
		Type:    TypeFile,
		TS:      millis(at),
		Process: basename(targetPath),
		Cmdline: targetPath,
	}
}

// DNS 는 DNS 질의 이벤트를 만든다.
//
// processPath 는 질의를 낸 프로세스의 실행 경로다. 알 수 없으면 비운다. Windows 는 ETW 가
// 프로세스를 알려주지만 패킷에서 뽑을 때는 누가 낸 질의인지 알 수 없다.
//
// detail 에는 질의 타입과 응답 IP 목록 같은 부가정보를 넣는다.
func (f Factory) DNS(at time.Time, processPath, domain string, detail map[string]any) Event {
	return Event{
		Host:    f.Host,
		Type:    TypeDNS,
		TS:      millis(at),
		Process: basename(processPath),
		Domain:  domain,
		Detail:  encodeDetail(detail),
	}
}

// L7 은 TLS 핸드셰이크에서 뽑은 메타데이터 이벤트를 만든다.
//
// domain 은 ClientHello 의 SNI 이고 인증서 정보는 detail 에 넣는다.
// 페이로드 자체는 절대 담지 않는다. 통신 내용을 서버로 보내는 것은 수집이 아니라 감청이다.
func (f Factory) L7(at time.Time, processPath, domain, destIP string, destPort int, detail map[string]any) Event {
	return Event{
		Host:     f.Host,
		Type:     TypeL7,
		TS:       millis(at),
		Process:  basename(processPath),
		DestIP:   destIP,
		DestPort: destPort,
		Domain:   domain,
		Detail:   encodeDetail(detail),
	}
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
