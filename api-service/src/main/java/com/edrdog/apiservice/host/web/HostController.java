package com.edrdog.apiservice.host.web;

import com.edrdog.apiservice.auth.service.AuthService;
import com.edrdog.apiservice.auth.service.Principal;
import com.edrdog.apiservice.host.HostService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * 엔드포인트(호스트) 목록·상태 요약 REST. 세션 Bearer 토큰으로 인증하고 그 tenant 로만 격리한다
 * (EventQueryController/AlertController 와 동일 패턴). 호스트 대장 없이 events+alerts 집계로 관측 호스트를 준다.
 */
@RestController
@RequestMapping("/api/hosts")
@Tag(name = "hosts", description = "관측 호스트 목록 및 상태 요약 (events+alerts 집계, tenant 격리)")
public class HostController {

    private static final String BEARER_PREFIX = "Bearer ";

    private final HostService hosts;
    private final AuthService auth;

    public HostController(HostService hosts, AuthService auth) {
        this.hosts = hosts;
        this.auth = auth;
    }

    @Operation(summary = "호스트 목록",
            description = "로그인 유저의 tenant 관측 호스트를 last_seen 최신순으로. 각 host 의 status(정상|주의|위험)와 위협수(열린 alert 수) 포함.")
    @GetMapping
    public List<HostResponse> list(
            @RequestHeader(name = "Authorization", required = false) String authorization) {
        return hosts.hosts(currentTenantId(authorization));
    }

    @Operation(summary = "호스트 상태 요약",
            description = "대시보드 도넛용. 로그인 유저의 tenant 호스트를 정상/주의/위험 수와 총 관측 호스트 수로 집계.")
    @GetMapping("/summary")
    public HostSummary summary(
            @RequestHeader(name = "Authorization", required = false) String authorization) {
        return hosts.summary(currentTenantId(authorization));
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
}
