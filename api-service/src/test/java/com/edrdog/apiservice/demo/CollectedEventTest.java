package com.edrdog.apiservice.demo;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * events 토픽 발행 형태를 못박는다. detector 는 자기 사본 레코드(Event)로 역직렬화하므로 필드명이
 * 하나라도 어긋나면 그 필드가 null 로 들어가 <b>아무 alert 도 안 뜨고 조용히 실패</b>한다.
 *
 * <p>detector 쪽 짝은 DemoCollectContractTest(같은 JSON 을 토폴로지에 흘려 alert 를 확인). 이 두 테스트가
 * 같은 문자열을 각자 적고 있어야 한쪽만 바뀌었을 때 드러난다.
 */
class CollectedEventTest {

    private final ObjectMapper mapper = new ObjectMapper();   // EventsProducer 와 같은 기본 설정

    @Test
    void process_이벤트_직렬화_형태() throws Exception {
        CollectedEvent event = CollectedEvent.process("PC-01", 1000L, "powershell.exe", "winword.exe",
                "powershell -enc AAA", "99");

        assertEquals("{\"host\":\"PC-01\",\"type\":\"process\",\"ts\":1000,\"process\":\"powershell.exe\","
                        + "\"parent\":\"winword.exe\",\"cmdline\":\"powershell -enc AAA\","
                        + "\"destIp\":null,\"destPort\":0,\"tenantId\":\"99\"}",
                mapper.writeValueAsString(event));
    }

    @Test
    void network_이벤트_직렬화_형태() throws Exception {
        CollectedEvent event = CollectedEvent.network("PC-01", 1000L, "chrome.exe", "185.220.101.5", 443, "99");

        assertEquals("{\"host\":\"PC-01\",\"type\":\"network\",\"ts\":1000,\"process\":\"chrome.exe\","
                        + "\"parent\":null,\"cmdline\":null,\"destIp\":\"185.220.101.5\","
                        + "\"destPort\":443,\"tenantId\":\"99\"}",
                mapper.writeValueAsString(event));
    }
}
