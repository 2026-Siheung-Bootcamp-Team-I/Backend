package packet

import (
	"net"
	"strconv"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// DNSMessage 는 DNS 패킷에서 뽑은 메타데이터다. 원본 바이트는 담지 않는다.
type DNSMessage struct {
	Domain     string   // 질의 이름. 소문자, 후행 점 제거
	QueryType  string   // "A", "AAAA", "CNAME" 등. 모르면 숫자 문자열
	Answers    []string // 응답 IP. 질의 패킷이면 비어 있다
	IsResponse bool
}

// ParseDNS 는 UDP 페이로드에서 DNS 질의 이름과 응답 IP 를 꺼낸다.
// 파싱을 손으로 하면 이름 압축 포인터가 서로를 가리킬 때 무한 루프에 빠진다. dnsmessage 에 맡긴다.
func ParseDNS(payload []byte) (DNSMessage, bool) {
	var p dnsmessage.Parser
	header, err := p.Start(payload)
	if err != nil {
		return DNSMessage{}, false
	}

	// 질의가 없는 메시지는 어디에 접속하려 했는지 말해 주지 않는다. 버린다.
	q, err := p.Question()
	if err != nil {
		return DNSMessage{}, false
	}

	domain := normalizeDomain(q.Name.String())
	if domain == "" || isReverseLookup(domain) {
		return DNSMessage{}, false
	}

	msg := DNSMessage{
		Domain:     domain,
		QueryType:  queryTypeName(q.Type),
		IsResponse: header.Response,
	}
	if !header.Response {
		return msg, true
	}

	// 답을 읽으려면 남은 질의를 먼저 넘겨야 한다. 파서가 섹션 순서대로만 진행한다.
	if err := p.SkipAllQuestions(); err != nil {
		return msg, true
	}
	msg.Answers = answerIPs(&p)
	return msg, true
}

// answerIPs 는 응답 섹션에서 A/AAAA 레코드의 IP 만 모은다.
// 도중에 깨진 레코드를 만나면 거기서 멈추고 그때까지 모은 것을 돌려준다.
func answerIPs(p *dnsmessage.Parser) []string {
	var ips []string
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			return ips
		}
		switch h.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return ips
			}
			ips = append(ips, net.IP(r.A[:]).String())
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return ips
			}
			ips = append(ips, net.IP(r.AAAA[:]).String())
		default:
			if err := p.SkipAnswer(); err != nil {
				return ips
			}
		}
	}
}

// normalizeDomain 은 도메인을 소문자로 낮추고 후행 점을 뗀다.
// 정규화를 빼면 Example.COM 과 example.com 이 갈려 한 도메인이 여러 건으로 집계된다.
func normalizeDomain(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// isReverseLookup 은 IP 를 이름으로 바꾸는 질의인지 본다.
// 이 필터를 빼면 "어디에 접속했나" 와 무관한 역방향 조회가 정방향 질의만큼 쏟아져 들어온다.
func isReverseLookup(domain string) bool {
	return strings.HasSuffix(domain, ".in-addr.arpa") || strings.HasSuffix(domain, ".ip6.arpa") ||
		domain == "in-addr.arpa" || domain == "ip6.arpa"
}

// queryTypeName 은 질의 타입을 사람이 읽는 이름으로 바꾼다. 모르는 타입은 숫자 문자열로 둔다.
func queryTypeName(t dnsmessage.Type) string {
	switch t {
	case dnsmessage.TypeA:
		return "A"
	case dnsmessage.TypeAAAA:
		return "AAAA"
	case dnsmessage.TypeCNAME:
		return "CNAME"
	case dnsmessage.TypeNS:
		return "NS"
	case dnsmessage.TypeMX:
		return "MX"
	case dnsmessage.TypeTXT:
		return "TXT"
	case dnsmessage.TypePTR:
		return "PTR"
	case dnsmessage.TypeSOA:
		return "SOA"
	case dnsmessage.TypeSRV:
		return "SRV"
	}
	return strconv.Itoa(int(t))
}
