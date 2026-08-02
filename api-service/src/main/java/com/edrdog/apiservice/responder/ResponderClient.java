package com.edrdog.apiservice.responder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * responder-service 내부 API 호출 래퍼(kill 위임).
 * responder 에는 앱 레벨 인증이 없어, 접근 통제는 이 프록시의 Bearer 세션 인증 + tenant 소유 검증(AlertController)이 전부다.
 */
@Component
public class ResponderClient {

    private static final Logger log = LoggerFactory.getLogger(ResponderClient.class);

    private final RestClient http;

    public ResponderClient(@Value("${edrdog.responder.url}") String baseUrl) {
        this.http = RestClient.builder().baseUrl(baseUrl).build();
    }

    /**
     * host 의 target 프로세스 kill 을 responder 에 요청하고 실행 결과를 그대로 돌려준다.
     * 연결 실패·4xx/5xx·빈 응답을 FAILED 로 매핑한다. 그냥 던지면 불투명한 500 이 나가고,
     * 반대로 KILLED 로 두면 종료되지 않은 프로세스를 처리 완료로 넘긴다(fail-closed).
     */
    public KillResult kill(String host, String target) {
        try {
            KillResult result = http.post()
                    .uri("/api/responder/kill")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(new KillCommand(host, target))
                    .retrieve()
                    .body(KillResult.class);
            return result != null ? result : new KillResult(host, target, "FAILED", null);
        } catch (RestClientException e) {
            log.error("responder kill 위임 실패 host={} target={} err={}", host, target, e.toString());
            return new KillResult(host, target, "FAILED", null);
        }
    }

    /** responder kill 요청 본문(responder KillController.KillRequest 와 동일 필드). */
    private record KillCommand(String host, String target) {
    }
}
