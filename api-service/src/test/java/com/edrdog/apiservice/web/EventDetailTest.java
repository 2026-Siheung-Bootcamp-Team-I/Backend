package com.edrdog.apiservice.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * events.detail JSON 문자열 -> named 필드 매핑의 순수 로직 검증.
 * 관측하지 않은 값과 0/빈 값을 구분하는 것(agent 쪽 event.go 의 원칙)이 핵심이라
 * "키가 아예 없을 때"와 "키가 0/빈 값으로 있을 때"를 각각 검증한다.
 */
class EventDetailTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void 프로세스_실행_detail_에서_pid_ppid_를_읽는다() {
        EventDetail d = EventDetail.parse("{\"pid\":123,\"ppid\":456}", mapper);
        assertEquals(123, d.pid());
        assertEquals(456, d.ppid());
    }

    @Test
    void pid_가_없으면_0_이_아니라_null_이다() {
        EventDetail d = EventDetail.parse("{\"protocol\":\"tcp\"}", mapper);
        assertNull(d.pid());
        assertNull(d.ppid());
        assertEquals("tcp", d.protocol());
    }

    @Test
    void 파일_이벤트_detail_에서_action_을_읽는다() {
        EventDetail d = EventDetail.parse("{\"action\":\"CREATE\"}", mapper);
        assertEquals("CREATE", d.action());
    }

    @Test
    void dns_응답_status_0_은_관측된_성공값이라_null_이_아니다() {
        EventDetail d = EventDetail.parse(
                "{\"queryType\":\"A\",\"answers\":[\"1.2.3.4\",\"5.6.7.8\"],\"status\":0}", mapper);
        assertEquals("A", d.queryType());
        assertEquals(List.of("1.2.3.4", "5.6.7.8"), d.answers());
        assertEquals(0, d.status());
    }

    @Test
    void dns_응답이_없으면_answers_는_null_이다() {
        EventDetail d = EventDetail.parse("{\"queryType\":\"A\",\"status\":3}", mapper);
        assertNull(d.answers());
        assertEquals(3, d.status());
    }

    @Test
    void tls_detail_에서_버전과_alpn_을_읽는다() {
        EventDetail d = EventDetail.parse(
                "{\"l7Protocol\":\"TLS\",\"tlsVersion\":\"TLS1.3\",\"alpn\":[\"h2\",\"http/1.1\"]}", mapper);
        assertEquals("TLS", d.l7Protocol());
        assertEquals("TLS1.3", d.tlsVersion());
        assertEquals(List.of("h2", "http/1.1"), d.alpn());
    }

    @Test
    void http_detail_에서_메서드_경로_ua_상태코드를_읽는다() {
        EventDetail d = EventDetail.parse(
                "{\"l7Protocol\":\"HTTP\",\"httpMethod\":\"GET\",\"httpPath\":\"/foo\","
                        + "\"httpUserAgent\":\"curl/8.0\",\"httpStatusCode\":200}", mapper);
        assertEquals("HTTP", d.l7Protocol());
        assertEquals("GET", d.httpMethod());
        assertEquals("/foo", d.httpPath());
        assertEquals("curl/8.0", d.httpUserAgent());
        assertEquals(200, d.httpStatusCode());
    }

    @Test
    void httpStatusCode_가_없으면_0_이_아니라_null_이다() {
        EventDetail d = EventDetail.parse("{\"l7Protocol\":\"HTTP\",\"httpMethod\":\"GET\"}", mapper);
        assertNull(d.httpStatusCode());
    }

    @Test
    void 빈_문자열_detail_은_모든_필드가_null_이다() {
        EventDetail d = EventDetail.parse("", mapper);
        assertAllNull(d);
    }

    @Test
    void null_detail_은_모든_필드가_null_이다() {
        EventDetail d = EventDetail.parse(null, mapper);
        assertAllNull(d);
    }

    @Test
    void 깨진_JSON_detail_은_예외_없이_모든_필드가_null_이다() {
        EventDetail d = EventDetail.parse("{이건 JSON 이 아니다", mapper);
        assertAllNull(d);
    }

    @Test
    void 모르는_키가_섞여도_예외_없이_아는_키만_읽는다() {
        EventDetail d = EventDetail.parse("{\"pid\":1,\"futureKey\":\"x\"}", mapper);
        assertEquals(1, d.pid());
    }

    private static void assertAllNull(EventDetail d) {
        assertNull(d.pid());
        assertNull(d.ppid());
        assertNull(d.protocol());
        assertNull(d.action());
        assertNull(d.queryType());
        assertNull(d.answers());
        assertNull(d.status());
        assertNull(d.tlsVersion());
        assertNull(d.alpn());
        assertNull(d.l7Protocol());
        assertNull(d.httpMethod());
        assertNull(d.httpPath());
        assertNull(d.httpUserAgent());
        assertNull(d.httpStatusCode());
    }
}
