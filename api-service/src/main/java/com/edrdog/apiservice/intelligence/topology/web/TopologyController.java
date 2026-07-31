package com.edrdog.apiservice.intelligence.topology.web;

import com.edrdog.apiservice.auth.service.AuthService;
import com.edrdog.apiservice.auth.service.Principal;
import com.edrdog.apiservice.intelligence.topology.TopologyService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * egress 토폴로지(엔드포인트→외부 목적지) 그래프 REST.
 * 세션 Bearer 토큰으로 인증하고 그 tenant 로만 격리한다(EventQueryController 와 동일 패턴).
 */
@RestController
@RequestMapping("/api/intelligence")
@Tag(name = "intelligence", description = "관계 분석 (events+alerts 집계, tenant 격리)")
public class TopologyController {

    private static final String BEARER_PREFIX = "Bearer ";

    /** 기본 조회 구간: 최근 24시간(HostController.processTree 와 같은 기본값). */
    private static final long DEFAULT_WINDOW_MS = 24 * 60 * 60 * 1000L;

    private final TopologyService topology;
    private final AuthService auth;

    public TopologyController(TopologyService topology, AuthService auth) {
        this.topology = topology;
        this.auth = auth;
    }

    @Operation(summary = "egress 토폴로지",
            description = "엔드포인트가 외부 목적지(도메인 또는 IP)로 나간 관계를 그래프(nodes/edges)로 준다. "
                    + "엣지에는 이벤트 수·알림 수·관측된 프로토콜 라벨이 실리고, 알림 수 0 은 관측만 된 관계다. "
                    + "같은 등록가능 도메인(eTLD+1)을 쓰는 목적지가 둘 이상이면 domainGroup 노드로 묶는다. "
                    + "엔드포인트 노드의 riskScore(0..100)는 기간 내 열린 alert 를 severity 로 가중합한 값이다. "
                    + "from/to(epoch millis) 미지정 시 최근 24시간, limit(관계 수) 기본 200·상한 1000이며 "
                    + "잘린 경우 totalRelations/shownRelations/truncated 로 드러난다. q 는 호스트·목적지 부분 일치.")
    @GetMapping("/topology")
    public TopologyResponse topology(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @RequestParam(required = false) Long from,
            @RequestParam(required = false) Long to,
            @RequestParam(required = false) String q,
            @RequestParam(required = false) Integer limit) {
        String tenantId = currentTenantId(authorization);
        long resolvedTo = to != null ? to : System.currentTimeMillis();
        long resolvedFrom = from != null ? from : resolvedTo - DEFAULT_WINDOW_MS;
        return topology.topology(tenantId, resolvedFrom, resolvedTo, q, limit);
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
}
