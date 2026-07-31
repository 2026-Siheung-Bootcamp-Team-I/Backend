package com.edrdog.apiservice.alert.web;

import com.edrdog.apiservice.alert.AlertQueryBuilder;
import com.edrdog.apiservice.alert.AlertService;
import com.edrdog.apiservice.alert.AlertStatus;
import com.edrdog.apiservice.auth.exception.AuthException;
import com.edrdog.apiservice.auth.service.AuthService;
import com.edrdog.apiservice.auth.service.Principal;
import com.edrdog.apiservice.incident.IncidentService;
import com.edrdog.apiservice.query.TimeBucket;
import com.edrdog.apiservice.responder.KillResult;
import com.edrdog.apiservice.responder.ResponderClient;
import com.edrdog.apiservice.web.PageHeaders;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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
    private final IncidentService incidents;

    public AlertController(AlertService alerts, AuthService auth, ResponderClient responder,
                           IncidentService incidents) {
        this.alerts = alerts;
        this.auth = auth;
        this.responder = responder;
        this.incidents = incidents;
    }

    @Operation(summary = "알림 목록",
            description = "로그인 유저의 tenant 것만 host/severity/status/domain/destIp/from/to 필터로 최신순 조회. "
                    + "domain/destIp 는 알림이 실은 목적지 필터라 관계 분석 화면에서 도메인을 짚은 뒤 "
                    + "그 도메인 때문에 난 알림으로 넘어갈 때 쓴다. 대소문자 무관하게 도메인을 찾는다. limit 기본 100, 상한 1000.\n\n"
                    + "페이지네이션: offset 으로 건너뛴다(기본 0, 상한 " + AlertQueryBuilder.MAX_OFFSET + "). "
                    + "상한을 넘으면 400 이며, 더 깊이 파야 하면 offset 을 키우는 대신 from/to 로 범위를 좁혀라. "
                    + "응답 본문은 지금과 같은 배열이고 페이지 정보는 헤더로 나간다: "
                    + "X-Has-More(다음 페이지 유무), X-Time-From/X-Time-To(이 응답에 실제로 적용된 시간 범위), "
                    + "withTotal=true 일 때만 X-Total-Count(전체 건수).\n\n"
                    + "**다음 페이지를 부를 때는 첫 응답의 X-Time-To 를 to 에 그대로 실어야 한다.** "
                    + "조회가 최신순이라 그사이 새 알림이 맨 위에 쌓이면 offset 이 밀려서 행이 겹치거나 건너뛰어진다. "
                    + "to 를 안 주면 서버가 요청 시각으로 고정해 적용하고 그 값을 X-Time-To 로 알려 준다. "
                    + "총 건수는 FINAL(중복 제거) 위에서 count() 를 한 번 더 도는 것이라 기본으로는 세지 않는다.")
    @GetMapping
    public ResponseEntity<List<AlertResponse>> list(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @RequestParam(required = false) String host,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String domain,
            @RequestParam(required = false) String destIp,
            @RequestParam(required = false) Long from,
            @RequestParam(required = false) Long to,
            @RequestParam(required = false) Integer limit,
            @RequestParam(required = false) Integer offset,
            @RequestParam(required = false, defaultValue = "false") boolean withTotal) {
        requireValidOffset(offset);
        // to 를 안 준 첫 페이지를 여기서 고정해야 다음 페이지가 같은 범위를 볼 수 있다.
        long resolvedTo = to != null ? to : System.currentTimeMillis();
        String tenantId = currentTenantId(authorization);
        AlertService.AlertPage page = alerts.query(tenantId, host, severity, status, domain, destIp,
                from, resolvedTo, limit, offset, withTotal);
        return PageHeaders.body(page.items(), page.hasMore(), page.total(),
                from != null ? from : 0L, resolvedTo);
    }

    /** 상한을 넘은 offset 은 조용히 자르지 않고 400 으로 거절한다(자르면 화면이 빈 페이지로 읽는다). */
    private static void requireValidOffset(Integer offset) {
        if (offset != null && (offset < 0 || offset > AlertQueryBuilder.MAX_OFFSET)) {
            throw AuthException.invalidInput("offset 은 0.." + AlertQueryBuilder.MAX_OFFSET + " 여야 합니다: " + offset);
        }
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

    @Operation(summary = "알림 상세",
            description = "단건 상세(matched + 판정을 유발한 원본 이벤트 sourceEvent 포함, 못 찾으면 null). "
                    + "sourceEvent.matchedBy 는 그 이벤트를 무엇으로 특정했는지이며 summary 가 rule_type 보다 확신이 강하다"
                    + "(rule_type 은 이벤트 종류만 맞춘 것이라 같은 종류가 여럿이면 시각으로 갈렸다). "
                    + "이 알림이 속한 사건의 incidentId 도 함께 준다(기본 기간인 최근 7일 안에서 못 찾으면 null). "
                    + "남의 tenant 것이면 404.")
    @GetMapping("/{id}")
    public AlertResponse detail(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @PathVariable String id) {
        String tenantId = currentTenantId(authorization);
        // 사건 id 는 incident 쪽에서 오므로 조립을 여기서 한다. 지금 의존 방향이 incident → alert 라
        // (IncidentService 가 AlertQueryBuilder 등을 쓴다) AlertService 가 IncidentService 를 부르면
        // 서비스 계층에 양방향 순환이 생긴다. 웹 계층은 양쪽을 다 알아도 되는 자리다.
        return alerts.get(tenantId, id).withIncidentId(incidents.incidentIdOf(tenantId, id));
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
        KillResult result = responder.kill(alert.host(), request.target());
        // 실패했는데 CONFIRMED 로 바꾸면 처리된 것처럼 보이므로, kill 성공했을 때만 갱신해 재조치를 막는다.
        if (result.killed()) {
            alerts.triage(tenantId, id, AlertStatus.CONFIRMED);
        }
        return result;
    }

    /** Bearer 토큰을 검증해 현재 유저의 tenant 를 문자열로 반환. 토큰이 없거나 만료면 AuthService 가 401. */
    private String currentTenantId(String authorization) {
        Principal principal = auth.resolve(bearerToken(authorization));
        return String.valueOf(principal.tenantId());
    }

    private static String bearerToken(String authorization) {
        if (authorization == null || !authorization.startsWith(BEARER_PREFIX)) {
            return null;
        }
        return authorization.substring(BEARER_PREFIX.length()).trim();
    }

    public record TriageRequest(String status) {
    }

    /** host 는 알림에서 가져오므로 클라이언트가 지정하지 않는다(target 만 받음). */
    public record RespondRequest(String target) {
    }
}
