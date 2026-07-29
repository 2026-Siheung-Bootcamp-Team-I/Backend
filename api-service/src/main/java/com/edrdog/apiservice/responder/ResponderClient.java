package com.edrdog.apiservice.responder;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.util.List;

/**
 * responder-service 내부 API 호출 래퍼(kill 위임과 에이전트 명령 중계).
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

    /**
     * host 의 대기 중인 대응 명령을 responder 에서 가져온다(하트비트 응답에 실어 내려준다).
     *
     * <p>responder 가 죽어 있거나 오류를 주면 빈 리스트로 답한다. 조치를 못 받는 것보다
     * 하트비트가 실패해 수집까지 멈추는 쪽이 더 나쁘다.
     */
    public List<AgentCommand> pendingCommands(String host) {
        try {
            AgentCommand[] commands = http.get()
                    .uri(uri -> uri.path("/api/responder/commands").queryParam("host", host).build())
                    .retrieve()
                    .body(AgentCommand[].class);
            return commands == null ? List.of() : List.of(commands);
        } catch (RestClientException e) {
            log.error("responder 대기 명령 조회 실패 host={} err={}", host, e.toString());
            return List.of();
        }
    }

    /**
     * 에이전트가 보고한 명령 실행 결과를 responder 로 넘긴다(대기 중인 kill 요청을 깨우는 신호다).
     * 실패하면 로그만 남긴다. 여기서 예외를 올려도 이미 실행된 조치를 되돌릴 수 없고,
     * 결과를 못 받은 responder 는 어차피 TIMEOUT 으로 정리한다.
     */
    public void reportCommandResult(String commandId, String status, String message) {
        try {
            http.post()
                    .uri("/api/responder/commands/result")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(new CommandResult(commandId, status, message))
                    .retrieve()
                    .toBodilessEntity();
        } catch (RestClientException e) {
            log.error("responder 명령 결과 전달 실패 commandId={} status={} err={}", commandId, status, e.toString());
        }
    }

    /** responder kill 요청 본문(responder KillController.KillRequest 와 동일 필드). */
    private record KillCommand(String host, String target) {
    }

    /** responder 명령 결과 보고 본문. 프로토콜과 같은 snake_case 로 보낸다. */
    private record CommandResult(
            @JsonProperty("command_id") String commandId,
            @JsonProperty("status") String status,
            @JsonProperty("message") String message
    ) {
    }
}
