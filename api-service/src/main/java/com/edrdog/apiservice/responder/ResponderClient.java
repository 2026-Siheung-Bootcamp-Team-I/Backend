package com.edrdog.apiservice.responder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * responder-service 내부 kill 엔드포인트 호출 래퍼.
 *
 * <p>responder 는 클러스터 내부(ClusterIP)로만 노출되고 앱 레벨 인증이 없다. 접근 통제는 이 프록시
 * (api-service)의 Bearer 세션 인증 + tenant 소유 검증으로 대신한다(AlertController).
 * 다른 내부 RestClient(ClickHouseReader 등)와 같은 per-component builder 패턴을 따른다.
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
     * responder 가 죽어있거나 오류를 주면(연결 실패·4xx/5xx) 불투명한 500 대신 FAILED 결과로 매핑한다
     * (responder 상태 어휘와 동일). 실패해도 실제 kill 은 일어나지 않으므로 fail-closed 다.
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
