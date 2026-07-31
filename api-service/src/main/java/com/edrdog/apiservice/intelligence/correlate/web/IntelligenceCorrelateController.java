package com.edrdog.apiservice.intelligence.correlate.web;

import com.edrdog.apiservice.auth.service.AuthService;
import com.edrdog.apiservice.auth.service.Principal;
import com.edrdog.apiservice.intelligence.correlate.CorrelateResponse;
import com.edrdog.apiservice.intelligence.correlate.CorrelateService;
import com.edrdog.apiservice.intelligence.correlate.CorrelateTarget;
import com.edrdog.apiservice.intelligence.correlate.DnsLookupResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * 도메인/IP 하나를 기준으로 얽힌 관계를 보여 주는 읽기 전용 REST.
 * 관측 조회는 세션 Bearer 토큰의 tenant 로만 격리한다(EventQueryController 와 같은 패턴).
 *
 * <p>실시간 DNS 조회에는 tenant 개념이 없다. 우리 데이터가 아니라 외부에 묻는 것이라 격리와
 * 무관하다. 대신 사용자가 준 문자열을 그대로 질의에 싣지 않도록 형식을 먼저 검증한다.
 */
@RestController
@RequestMapping("/api/intelligence")
@Tag(name = "intelligence", description = "도메인·IP 관계 분석과 실시간 DNS 조회")
public class IntelligenceCorrelateController {

    private static final String BEARER_PREFIX = "Bearer ";

    private final CorrelateService service;
    private final AuthService auth;

    public IntelligenceCorrelateController(CorrelateService service, AuthService auth) {
        this.service = service;
        this.auth = auth;
    }

    @Operation(summary = "도메인·IP 관계 분석",
            description = "target(도메인 또는 IP)과 얽힌 관계를 그래프로 준다. 모든 엣지는 출처(origin)를 달고 나간다: "
                    + "OBSERVED 는 우리가 수집한 이벤트에서 나온 관계, LIVE_DNS 는 지금 DNS 서버에 물어본 결과, "
                    + "INFERRED 는 관측 두 건을 이어 붙여 추측한 것(프로세스가 빈 macOS DNS 이벤트의 질의자 보정)이다. "
                    + "관측 조회는 로그인 유저의 tenant 것만 본다. liveDns=false 로 실시간 조회를 끌 수 있다.")
    @GetMapping("/correlate")
    public CorrelateResponse correlate(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @RequestParam String target,
            @RequestParam(required = false) Long from,
            @RequestParam(required = false) Long to,
            @RequestParam(required = false) Integer limit,
            @RequestParam(required = false, defaultValue = "true") boolean liveDns) {
        String tenantId = currentTenantId(authorization);
        return service.correlate(tenantId, parseTarget(target), from, to, limit, liveDns);
    }

    @Operation(summary = "실시간 DNS 조회",
            description = "도메인이면 정방향(A/AAAA), IP 면 역방향(PTR)을 지금 조회한다. "
                    + "PTR 결과(ptrNames)는 후보일 뿐이며 그 IP 의 정체를 증명하지 않는다. IP 를 대체하는 값이 아니다. "
                    + "조회가 실패해도 500 이 아니라 status=FAILED 로 담아 200 으로 준다.")
    @GetMapping("/dns-lookup")
    public DnsLookupResponse dnsLookup(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @RequestParam String target) {
        // 외부 조회라 tenant 는 안 쓰지만 로그인 여부는 다른 조회 API 와 동일하게 검사한다.
        auth.resolve(bearerToken(authorization));
        return service.lookup(parseTarget(target));
    }

    private static CorrelateTarget parseTarget(String target) {
        try {
            return CorrelateTarget.parse(target);
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        }
    }

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
