package com.edrdog.apiservice.notify;

import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.Map;

/**
 * 개인 Slack Incoming Webhook 으로 직접 POST 한다.
 * 실패를 삼키지 않고 Slack 이 준 HTTP 상태코드를 그대로 돌려준다(테스트 알림 API 가 실제 도달 여부를 판단해야 한다).
 */
@Component
public class SlackWebhookClient {

    // 요청 스레드가 오래 붙잡히지 않도록 연결/읽기를 짧게 자른다.
    private static final int TIMEOUT_MS = 3000;

    private final RestClient client;

    public SlackWebhookClient(RestClient.Builder builder) {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(TIMEOUT_MS);
        factory.setReadTimeout(TIMEOUT_MS);
        this.client = builder.requestFactory(factory).build();
    }

    /**
     * webhookUrl 로 {"text": text} 를 POST 하고 Slack 이 응답한 HTTP 상태코드를 돌려준다.
     * 4xx/5xx 는 예외 대신 상태코드로 나가고(호출측이 판단), 연결 실패/타임아웃만 RestClientException 으로 전파된다.
     */
    public int send(String webhookUrl, String text) {
        ResponseEntity<Void> response = client.post()
                .uri(webhookUrl)
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("text", text))
                .retrieve()
                .onStatus(HttpStatusCode::isError, (req, res) -> { })
                .toBodilessEntity();
        return response.getStatusCode().value();
    }
}
