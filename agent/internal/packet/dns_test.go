package packet

import (
	"bytes"
	"net"
	"slices"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// 픽스처는 dnsmessage.Builder 로 만든다. 손으로 적은 16진수와 달리 이름 인코딩과 섹션 개수를
// 라이브러리가 맞춰 주므로 테스트가 틀린 바이트를 검증하는 일이 없다.

func mustName(t testing.TB, s string) dnsmessage.Name {
	t.Helper()
	n, err := dnsmessage.NewName(s)
	if err != nil {
		t.Fatalf("이름 %q 를 만들지 못했다: %v", s, err)
	}
	return n
}

func dnsQuery(t testing.TB, name string, typ dnsmessage.Type) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: mustName(t, name), Type: typ, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	raw, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// dnsResponse 는 질의 이름과 같은 이름으로 답을 채운다. 압축을 켜면 답의 이름이 질의 이름을
// 가리키는 포인터로 줄어드는데, 실제 리졸버 응답이 정확히 이 모양이다.
func dnsResponse(t testing.TB, name string, answers []dnsmessage.ResourceBody) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234, Response: true, RecursionAvailable: true})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	q := dnsmessage.Question{Name: mustName(t, name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	if err := b.Question(q); err != nil {
		t.Fatal(err)
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	for _, body := range answers {
		h := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}
		var err error
		switch r := body.(type) {
		case *dnsmessage.AResource:
			err = b.AResource(h, *r)
		case *dnsmessage.AAAAResource:
			err = b.AAAAResource(h, *r)
		case *dnsmessage.CNAMEResource:
			err = b.CNAMEResource(h, *r)
		default:
			t.Fatalf("픽스처가 다루지 않는 레코드 타입 %T", body)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	raw, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestParseDNSQuery(t *testing.T) {
	msg, ok := ParseDNS(dnsQuery(t, "www.example.com.", dnsmessage.TypeA))
	if !ok {
		t.Fatal("ParseDNS 가 false 를 돌려줬다")
	}
	if msg.Domain != "www.example.com" {
		t.Errorf("Domain = %q, want www.example.com", msg.Domain)
	}
	if msg.QueryType != "A" {
		t.Errorf("QueryType = %q, want A", msg.QueryType)
	}
	if msg.IsResponse {
		t.Error("질의를 응답으로 봤다")
	}
	if len(msg.Answers) != 0 {
		t.Errorf("Answers = %v, 질의에는 답이 없어야 한다", msg.Answers)
	}
}

func TestParseDNSQueryTypes(t *testing.T) {
	cases := map[dnsmessage.Type]string{
		dnsmessage.TypeA:     "A",
		dnsmessage.TypeAAAA:  "AAAA",
		dnsmessage.TypeCNAME: "CNAME",
		dnsmessage.TypeTXT:   "TXT",
		dnsmessage.Type(65):  "65", // HTTPS. 모르는 타입은 숫자로 남긴다
	}
	for typ, want := range cases {
		msg, ok := ParseDNS(dnsQuery(t, "example.com.", typ))
		if !ok {
			t.Fatalf("타입 %d 에서 false", typ)
		}
		if msg.QueryType != want {
			t.Errorf("QueryType = %q, want %q", msg.QueryType, want)
		}
	}
}

func TestParseDNSResponseCollectsIPs(t *testing.T) {
	raw := dnsResponse(t, "www.example.com.", []dnsmessage.ResourceBody{
		&dnsmessage.CNAMEResource{CNAME: mustName(t, "cdn.example.net.")},
		&dnsmessage.AResource{A: [4]byte{93, 184, 216, 34}},
		&dnsmessage.AAAAResource{AAAA: [16]byte(net.ParseIP("2606:2800:220:1:248:1893:25c8:1946").To16())},
	})

	msg, ok := ParseDNS(raw)
	if !ok {
		t.Fatal("ParseDNS 가 false 를 돌려줬다")
	}
	if !msg.IsResponse {
		t.Error("응답을 질의로 봤다")
	}
	want := []string{"93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"}
	if !slices.Equal(msg.Answers, want) {
		t.Errorf("Answers = %v, want %v", msg.Answers, want)
	}
}

// 압축 포인터를 손으로 따라가면 무한 루프에 빠지기 쉬워 라이브러리에 맡겼다.
// 픽스처가 실제로 포인터를 쓰는지부터 확인해야 이 테스트가 의미를 갖는다.
func TestParseDNSHandlesCompressedNames(t *testing.T) {
	raw := dnsResponse(t, "www.example.com.", []dnsmessage.ResourceBody{
		&dnsmessage.AResource{A: [4]byte{203, 0, 113, 7}},
	})

	// 압축 포인터는 상위 2비트가 켜진 바이트로 시작한다. 답의 이름이 질의 이름을 가리킨다.
	answerStart := bytes.Index(raw[12:], []byte{0xc0})
	if answerStart < 0 {
		t.Fatal("픽스처에 압축 포인터가 없다. 이 테스트가 검증할 것이 없다")
	}

	msg, ok := ParseDNS(raw)
	if !ok {
		t.Fatal("압축된 이름이 든 응답을 파싱하지 못했다")
	}
	if msg.Domain != "www.example.com" {
		t.Errorf("Domain = %q, want www.example.com", msg.Domain)
	}
	if !slices.Equal(msg.Answers, []string{"203.0.113.7"}) {
		t.Errorf("Answers = %v, want [203.0.113.7]", msg.Answers)
	}
}

// 대소문자가 섞여 오면 대시보드에서 같은 도메인이 여러 건으로 갈린다.
func TestParseDNSNormalizesDomain(t *testing.T) {
	msg, ok := ParseDNS(dnsQuery(t, "WWW.Example.COM.", dnsmessage.TypeA))
	if !ok {
		t.Fatal("ParseDNS 가 false 를 돌려줬다")
	}
	if msg.Domain != "www.example.com" {
		t.Errorf("Domain = %q, want www.example.com", msg.Domain)
	}
}

func TestParseDNSDropsReverseLookups(t *testing.T) {
	names := []string{
		"1.0.0.127.in-addr.arpa.",
		"7.113.0.203.in-addr.arpa.",
		"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
	}
	for _, name := range names {
		if _, ok := ParseDNS(dnsQuery(t, name, dnsmessage.TypePTR)); ok {
			t.Errorf("%q 는 역방향 조회라 걸러야 한다", name)
		}
	}
}

func TestParseDNSKeepsForwardArpaLookalikes(t *testing.T) {
	// arpa 로 끝나도 역방향 조회가 아닌 이름은 남겨야 한다.
	msg, ok := ParseDNS(dnsQuery(t, "www.arpa.", dnsmessage.TypeA))
	if !ok {
		t.Fatal("정방향 질의를 걸러 버렸다")
	}
	if msg.Domain != "www.arpa" {
		t.Errorf("Domain = %q, want www.arpa", msg.Domain)
	}
}

func TestParseDNSRejectsMessagesWithoutQuestion(t *testing.T) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, Response: true})
	raw, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := ParseDNS(raw); ok {
		t.Error("질의가 없는 메시지에 true 를 줬다")
	}
}

func TestParseDNSRejectsRootQuery(t *testing.T) {
	if _, ok := ParseDNS(dnsQuery(t, ".", dnsmessage.TypeNS)); ok {
		t.Error("루트 질의에는 도메인이 없으니 false 여야 한다")
	}
}

func TestParseDNSTruncatedNeverPanics(t *testing.T) {
	raw := dnsResponse(t, "www.example.com.", []dnsmessage.ResourceBody{
		&dnsmessage.AResource{A: [4]byte{203, 0, 113, 7}},
	})
	for i := range len(raw) {
		ParseDNS(raw[:i])
	}
	// 헤더까지만 온전한 메시지는 질의를 읽을 수 없으니 false 다.
	if _, ok := ParseDNS(raw[:12]); ok {
		t.Error("헤더만 있는 메시지에 true 를 줬다")
	}
}

// 답 섹션이 중간에서 잘려도 이미 읽은 IP 는 살린다. 뒤가 깨졌다고 앞을 버릴 이유가 없다.
func TestParseDNSKeepsAnswersReadBeforeTruncation(t *testing.T) {
	raw := dnsResponse(t, "www.example.com.", []dnsmessage.ResourceBody{
		&dnsmessage.AResource{A: [4]byte{203, 0, 113, 7}},
		&dnsmessage.AResource{A: [4]byte{203, 0, 113, 8}},
	})

	msg, ok := ParseDNS(raw[:len(raw)-8])
	if !ok {
		t.Fatal("앞부분이 온전한데 false 를 줬다")
	}
	if !slices.Equal(msg.Answers, []string{"203.0.113.7"}) {
		t.Errorf("Answers = %v, want [203.0.113.7]", msg.Answers)
	}
}

func TestParseDNSRejectsGarbage(t *testing.T) {
	cases := map[string][]byte{
		"빈 입력":    {},
		"짧은 입력":   {0x12, 0x34},
		"TLS 레코드": {0x16, 0x03, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5},
	}
	for name, raw := range cases {
		if _, ok := ParseDNS(raw); ok {
			t.Errorf("%s 에 true 를 줬다", name)
		}
	}
}

// UDP 페이로드가 그대로 ParseDNS 로 들어가는 실제 경로를 한 번 확인한다.
func TestParseDNSFromFullFrame(t *testing.T) {
	query := dnsQuery(t, "malware.example.org.", dnsmessage.TypeA)
	frame := ethernet(etherTypeIPv4, ipv4(protoUDP, "192.0.2.10", "203.0.113.53", nil, udp(51000, 53, query)))

	flow, payload, ok := Parse(frame, LinkEthernet)
	if !ok {
		t.Fatal("프레임을 벗기지 못했다")
	}
	if flow.DstPort != 53 {
		t.Fatalf("DstPort = %d, want 53", flow.DstPort)
	}

	msg, ok := ParseDNS(payload)
	if !ok {
		t.Fatal("페이로드에서 DNS 를 읽지 못했다")
	}
	if msg.Domain != "malware.example.org" {
		t.Errorf("Domain = %q, want malware.example.org", msg.Domain)
	}
}
