package sensor

import (
	"strconv"
	"strings"
)

// DNS-Client 질의완료 이벤트가 문자열로 실어 오는 이름과 응답을 읽는다.
// 프로바이더가 판마다 표기를 바꾸므로 못 알아본 값은 버리지 말고 원문 그대로 남긴다.

// normalizeDNSName 은 질의 이름을 집계할 수 있는 모양으로 맞춘다.
// 후행 점과 대소문자를 그대로 두면 같은 도메인이 대시보드에서 둘로 갈린다.
func normalizeDNSName(raw string) string {
	return strings.ToLower(strings.TrimRight(strings.TrimSpace(raw), "."))
}

// isReverseDNSName 은 IP 를 이름으로 되짚는 질의인지 본다.
func isReverseDNSName(name string) bool {
	return hasDNSSuffix(name, "in-addr.arpa") || hasDNSSuffix(name, "ip6.arpa")
}

// hasDNSSuffix 는 이름이 그 영역에 속하는지 본다.
// 라벨 경계까지 맞춘다. 단순 접미어 비교면 "notin-addr.arpa" 같은 이름까지 걸린다.
func hasDNSSuffix(name, suffix string) bool {
	return name == suffix || strings.HasSuffix(name, "."+suffix)
}

// dnsQueryTypeNames 는 자주 보는 레코드 종류다. 여기 없는 번호는 숫자 그대로 남긴다.
var dnsQueryTypeNames = map[int]string{
	1:   "A",
	2:   "NS",
	5:   "CNAME",
	6:   "SOA",
	12:  "PTR",
	15:  "MX",
	16:  "TXT",
	28:  "AAAA",
	33:  "SRV",
	64:  "SVCB",
	65:  "HTTPS",
	255: "ANY",
}

// dnsQueryTypeLabel 은 숫자로 오는 QueryType 을 이름으로 바꾼다. 모르는 번호는 그대로 둔다.
func dnsQueryTypeLabel(raw string) string {
	n, err := strconv.Atoi(raw)
	if err != nil {
		return raw
	}
	if name, ok := dnsQueryTypeNames[n]; ok {
		return name
	}
	return raw
}

// parseDNSAnswers 는 QueryResults 를 응답 값 목록으로 쪼갠다.
// 구분자를 실기기로 확인하지 못했다. 하나로 줄이면 잘못 짚었을 때 응답이 한 덩어리로 남는다.
func parseDNSAnswers(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool { return r == ';' || r == ',' })
	answers := make([]string, 0, len(fields))
	for _, field := range fields {
		if v := stripDNSResultPrefix(field); v != "" {
			answers = append(answers, v)
		}
	}
	if len(answers) == 0 {
		return nil
	}
	return answers
}

// stripDNSResultPrefix 는 "type: 5 alias.example.com" 처럼 값 앞에 붙는 레코드 종류를 뗀다.
// 번호 뒤에 공백이 없으면 IP 앞자리를 번호로 잘못 읽는 것이라 손대지 않는다.
func stripDNSResultPrefix(token string) string {
	v := strings.TrimSpace(token)

	const prefix = "type:"
	if len(v) < len(prefix) || !strings.EqualFold(v[:len(prefix)], prefix) {
		return v
	}
	v = strings.TrimSpace(v[len(prefix):])

	digits := 0
	for digits < len(v) && v[digits] >= '0' && v[digits] <= '9' {
		digits++
	}
	if digits == 0 || digits == len(v) {
		// 번호만 있고 값이 없으면 담을 것이 없다.
		return v[digits:]
	}
	if v[digits] != ' ' && v[digits] != '\t' {
		return v
	}
	return strings.TrimSpace(v[digits:])
}
