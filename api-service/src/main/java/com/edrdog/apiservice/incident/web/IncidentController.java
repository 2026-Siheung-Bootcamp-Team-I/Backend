package com.edrdog.apiservice.incident.web;

import com.edrdog.apiservice.auth.AuthException;
import com.edrdog.apiservice.auth.AuthService;
import com.edrdog.apiservice.auth.Principal;
import com.edrdog.apiservice.incident.IncidentPage;
import com.edrdog.apiservice.incident.IncidentService;
import com.edrdog.apiservice.web.PageHeaders;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * 사건 조회·트리아지 REST. 세션 Bearer 토큰으로 인증하고 그 tenant 로만 격리한다(AlertController 와 동일 패턴).
 * 남의 tenant 사건은 404 로 숨긴다. 단건 경로에도 from/to 가 있는 것은 조회할 때마다 기간 내 알림을 다시 묶기 때문이다.
 */
@RestController
@RequestMapping("/api/incidents")
@Tag(name = "incidents", description = "사건 조회 및 트리아지 (알림을 프로세스 계보로 묶어 조회 시 계산, tenant 격리)")
public class IncidentController {

    private static final String BEARER_PREFIX = "Bearer ";

    private final IncidentService incidents;
    private final AuthService auth;

    public IncidentController(IncidentService incidents, AuthService auth) {
        this.incidents = incidents;
        this.auth = auth;
    }

    @Operation(summary = "사건 목록",
            description = "로그인 유저의 tenant 알림을 프로세스 계보로 묶어 최근 활동순으로 준다. "
                    + "묶는 규칙은 조상-자손 관계이며(같은 프로세스이거나 한쪽이 다른 쪽을 띄웠을 때), "
                    + "이을 근거가 없으면 알림 하나짜리 사건이 된다. "
                    + "from/to(epoch millis) 미지정 시 최근 7일, status 는 open|confirmed|false_positive, "
                    + "host 는 정확히 일치하는 호스트만, limit 기본 100·상한 1000, offset 기본 0·상한 "
                    + IncidentService.MAX_OFFSET + "(넘으면 400). "
                    + "응답 본문은 지금과 같은 배열이고, withTotal=true 일 때만 X-Total-Count(필터를 통과한 "
                    + "전체 건수, offset/limit 로 자르기 전 값)가 헤더로 나간다. "
                    + "사건은 총계가 사실상 공짜지만 알림·이벤트 목록과 사용법을 맞추려고 같은 플래그를 받는다.")
    @GetMapping
    public ResponseEntity<List<IncidentResponse>> list(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String host,
            @RequestParam(required = false) Long from,
            @RequestParam(required = false) Long to,
            @RequestParam(required = false) Integer limit,
            @RequestParam(required = false) Integer offset,
            @RequestParam(required = false, defaultValue = "false") boolean withTotal) {
        String tenantId = currentTenantId(authorization);
        long resolvedTo = resolvedTo(to);
        IncidentPage page = incidents.query(tenantId, status, host,
                resolvedFrom(from, resolvedTo), resolvedTo, limit, offset, withTotal);
        // 본문 형태는 배열 그대로 두고 총 건수만 헤더로 얹는다. 안 셌으면(null) 헤더 자체가 없다.
        ResponseEntity.BodyBuilder response = ResponseEntity.ok();
        if (page.total() != null) {
            response.header(PageHeaders.TOTAL_COUNT, String.valueOf(page.total()));
        }
        return response.body(page.incidents());
    }

    @Operation(summary = "사건 상세",
            description = "구성 알림 전체와 사건 체인의 이벤트로만 그린 계보 그래프(nodes/edges)를 함께 준다. "
                    + "기간(from/to) 밖의 사건이거나 남의 tenant 것이면 404.")
    @GetMapping("/{id}")
    public IncidentResponse detail(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @PathVariable String id,
            @RequestParam(required = false) Long from,
            @RequestParam(required = false) Long to) {
        String tenantId = currentTenantId(authorization);
        long resolvedTo = resolvedTo(to);
        return incidents.get(tenantId, id, resolvedFrom(from, resolvedTo), resolvedTo);
    }

    @Operation(summary = "사건 전개(timeline)",
            description = "사건 체인에 속한 이벤트와 그 위에서 난 알림을 시간 오름차순으로 섞어 준다. "
                    + "같은 시각이면 이벤트가 먼저다. 체인 밖 이벤트는 담지 않는다. 남의 tenant 것이면 404.")
    @GetMapping("/{id}/timeline")
    public IncidentTimelineResponse timeline(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @PathVariable String id,
            @RequestParam(required = false) Long from,
            @RequestParam(required = false) Long to) {
        String tenantId = currentTenantId(authorization);
        long resolvedTo = resolvedTo(to);
        return incidents.timeline(tenantId, id, resolvedFrom(from, resolvedTo), resolvedTo);
    }

    @Operation(summary = "사건 트리아지",
            description = "status 를 confirmed/false_positive 로 갱신. 잘못된 값 400, 남의 tenant 것 404. "
                    + "사건 id 는 결정적이라 알림이 하나 더 붙어도 여기서 단 status 가 유지된다.")
    @PatchMapping("/{id}/status")
    public IncidentResponse triage(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @PathVariable String id,
            @RequestBody TriageRequest request,
            @RequestParam(required = false) Long from,
            @RequestParam(required = false) Long to) {
        String tenantId = currentTenantId(authorization);
        if (request == null || request.status() == null) {
            throw AuthException.invalidInput("status 가 필요합니다");
        }
        long resolvedTo = resolvedTo(to);
        return incidents.triage(tenantId, id, request.status(), resolvedFrom(from, resolvedTo), resolvedTo);
    }

    /** 기본 기간은 IncidentService 가 소유한다. 알림 상세의 incidentId 도 같은 창을 써야 id 가 일치한다. */
    private static long resolvedTo(Long to) {
        return IncidentService.resolveTo(to);
    }

    private static long resolvedFrom(Long from, long to) {
        return IncidentService.resolveFrom(from, to);
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
}
