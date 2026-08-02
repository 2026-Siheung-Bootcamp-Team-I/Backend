package com.edrdog.apiservice.operations.web;

import com.edrdog.apiservice.auth.AuthService;
import com.edrdog.apiservice.operations.OperationsHealthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 파이프라인(Kafka→ClickHouse) 상태 화면용 REST.
 * 세션 Bearer 토큰으로 로그인 여부만 보고, 운영 지표라 tenant 격리는 두지 않는다.
 */
@RestController
@RequestMapping("/api/operations")
@Tag(name = "operations", description = "파이프라인 상태(Kafka lag, ClickHouse 적재 지연, 의존 저장소 도달 여부)")
public class OperationsHealthController {

    private static final String BEARER_PREFIX = "Bearer ";

    private final OperationsHealthService service;
    private final AuthService auth;

    public OperationsHealthController(OperationsHealthService service, AuthService auth) {
        this.service = service;
        this.auth = auth;
    }

    @Operation(summary = "파이프라인 상태",
            description = "alerts/events 토픽의 컨슈머 lag, ClickHouse(edrdog.events/edrdog.alerts) 적재 지연, "
                    + "Kafka/ClickHouse/MySQL 도달 여부를 한 번에 준다. 항목 하나가 실패해도 나머지는 담아 200으로 준다.")
    @GetMapping("/health")
    public OperationsHealthResponse health(
            @RequestHeader(name = "Authorization", required = false) String authorization) {
        // 반환값을 안 쓴다고 지우면 운영 지표가 인증 없이 열린다. 토큰 없거나 만료면 여기서 401 이다.
        auth.resolve(bearerToken(authorization));
        return service.health();
    }

    private static String bearerToken(String authorization) {
        if (authorization == null || !authorization.startsWith(BEARER_PREFIX)) {
            return null;
        }
        return authorization.substring(BEARER_PREFIX.length()).trim();
    }
}
