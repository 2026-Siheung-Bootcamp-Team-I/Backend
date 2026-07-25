package com.edrdog.apiservice.alert.web;

import com.edrdog.apiservice.alert.AlertService;
import com.edrdog.apiservice.auth.exception.AuthException;
import com.edrdog.apiservice.auth.service.AuthService;
import com.edrdog.apiservice.auth.service.Principal;
import com.edrdog.apiservice.query.TimeBucket;
import com.edrdog.apiservice.responder.KillResult;
import com.edrdog.apiservice.responder.ResponderClient;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Set;

/**
 * alert 조회·트리아지 REST. 모든 요청은 세션 Bearer 토큰으로 인증하고 그 tenant 로만 격리한다
 * (EventQueryController 와 동일 패턴). 남의 tenant alert 는 404 로 숨긴다.
 */
@RestController
@RequestMapping("/api/alerts")
@Tag(name = "alerts", description = "알림 조회 및 트리아지 (ClickHouse 판정기록 + MySQL status 오버레이, tenant 격리)")
public class AlertController {

    private static final String BEARER_PREFIX = "Bearer ";
    private static final Set<String> VALID_BUCKETS = Set.of("hour", "day");
    private static final long DEFAULT_WINDOW_MS = 24 * 60 * 60 * 1000L;

    private final AlertService alerts;
    private final AuthService auth;
    private final ResponderClient responder;

    public AlertController(AlertService alerts, AuthService auth, ResponderClient responder) {
        this.alerts = alerts;
        this.auth = auth;
        this.responder = responder;
    }

    @Operation(summary = "알림 목록", description = "로그인 유저의 tenant 것만 host/severity/status/from/to 필터로 최신순 조회. limit 기본 100, 상한 1000.")
    @GetMapping
    public List<AlertResponse> list(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @RequestParam(required = false) String host,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) Long from,
            @RequestParam(required = false) Long to,
            @RequestParam(required = false) Integer limit) {
        String tenantId = currentTenantId(authorization);
        return alerts.query(tenantId, host, severity, status, from, to, limit);
    }

    @Operation(summary = "알림 대시보드 집계",
            description = "로그인 유저의 tenant 것만 기간(from/to 옵션)으로 total·severity 분포·카테고리별 상위 위협을 집계한다.")
    @GetMapping("/summary")
    public SummaryResponse summary(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @RequestParam(required = false) Long from,
            @RequestParam(required = false) Long to) {
        String tenantId = currentTenantId(authorization);
        return alerts.summary(tenantId, from, to);
    }

    @Operation(summary = "알림 시간대별 추이",
            description = "로그인 유저의 tenant 것만 bucket(hour|day) 간격으로 severity 별 탐지 추이를 집계한다. "
                    + "from/to 미지정 시 최근 24시간, 빈 버킷은 0으로 채운다.")
    @GetMapping("/timeseries")
    public List<TimeBucket> timeseries(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @RequestParam(required = false) Long from,
            @RequestParam(required = false) Long to,
            @RequestParam(required = false, defaultValue = "hour") String bucket) {
        if (!VALID_BUCKETS.contains(bucket)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "허용되지 않는 bucket 입니다: " + bucket);
        }
        long now = System.currentTimeMillis();
        long resolvedTo = to != null ? to : now;
        long resolvedFrom = from != null ? from : resolvedTo - DEFAULT_WINDOW_MS;
        String tenantId = currentTenantId(authorization);
        return alerts.timeseries(tenantId, resolvedFrom, resolvedTo, bucket);
    }

    @Operation(summary = "알림 상세", description = "단건 상세(matched 포함). 남의 tenant 것이면 404.")
    @GetMapping("/{id}")
    public AlertResponse detail(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @PathVariable String id) {
        String tenantId = currentTenantId(authorization);
        return alerts.get(tenantId, id);
    }

    @Operation(summary = "알림 공격 경로(lineage)",
            description = "알림 하나의 process lineage 그래프(nodes/edges). 같은 host+tenant 의 알림 시각 ±5분 events 를 "
                    + "이름 기반 process/network 체인으로 재구성한다. 남의 tenant 것이면 404.")
    @GetMapping("/{id}/lineage")
    public LineageResponse lineage(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @PathVariable String id) {
        String tenantId = currentTenantId(authorization);
        return alerts.lineage(tenantId, id);
    }

    @Operation(summary = "알림 트리아지", description = "status 를 confirmed/false_positive 로 갱신. 잘못된 값 400, 남의 tenant 것 404.")
    @PatchMapping("/{id}")
    public AlertResponse triage(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @PathVariable String id,
            @RequestBody TriageRequest request) {
        String tenantId = currentTenantId(authorization);
        return alerts.triage(tenantId, id, request.status());
    }

    @Operation(summary = "알림 실제 조치(kill)",
            description = "대시보드 실행 버튼용 반자동 조치. 로그인 유저의 tenant 가 소유한 알림일 때만(타 tenant 404) "
                    + "그 알림의 host 를 대상으로 target 프로세스 kill 을 responder 에 위임한다. host 는 알림에서 가져오므로 "
                    + "클라이언트가 지정할 수 없다. 실제 kill 실행 여부는 responder 실행 스위치(RESPONDER_EXECUTE_ENABLED)에 달려 있다.")
    @PostMapping("/{id}/respond")
    public KillResult respond(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @PathVariable String id,
            @RequestBody RespondRequest request) {
        String tenantId = currentTenantId(authorization);
        if (request == null || request.target() == null || request.target().isBlank()) {
            throw AuthException.invalidInput("target 프로세스가 필요합니다");
        }
        AlertResponse alert = alerts.get(tenantId, id);   // 타 tenant 면 404, 통과하면 권위 있는 host 확보
        return responder.kill(alert.host(), request.target());
    }

    /** Bearer 토큰을 검증해 현재 유저의 tenant 를 문자열로 반환. 토큰이 없거나 만료면 AuthService 가 401. */
    private String currentTenantId(String authorization) {
        Principal principal = auth.resolve(bearerToken(authorization));
        return String.valueOf(principal.tenantId());
    }

    /** "Bearer " 접두어를 떼서 토큰만 반환. 없으면 null. */
    private static String bearerToken(String authorization) {
        if (authorization == null || !authorization.startsWith(BEARER_PREFIX)) {
            return null;
        }
        return authorization.substring(BEARER_PREFIX.length()).trim();
    }

    /** PATCH 본문: 바꿀 status. */
    public record TriageRequest(String status) {
    }

    /** kill 요청 본문: 종료할 대상 프로세스명/경로. host 는 알림에서 가져오므로 클라이언트가 지정하지 않는다. */
    public record RespondRequest(String target) {
    }
}
