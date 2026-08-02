package com.edrdog.apiservice.alert.web;

import com.edrdog.apiservice.alert.ThreatCatalog;
import com.edrdog.apiservice.auth.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * 탐지 룰 카탈로그 조회 REST. 룰 설명은 정적 데이터라 알림 목록에 싣지 않고 별도 엔드포인트로 준다(프론트가 받아 캐시).
 */
@RestController
@RequestMapping("/api/alerts")
@Tag(name = "alerts", description = "알림 조회 및 트리아지 (ClickHouse 판정기록 + MySQL status 오버레이, tenant 격리)")
public class RuleCatalogController {

    private static final String BEARER_PREFIX = "Bearer ";

    private final AuthService auth;

    public RuleCatalogController(AuthService auth) {
        this.auth = auth;
    }

    @Operation(summary = "탐지 룰 카탈로그",
            description = "탐지 룰별 ruleId/한글 위협명/카테고리/MITRE 태그/발화 조건 설명을 반환한다. "
                    + "설명은 detector-service 의 룰 판정 로직에서 그대로 옮긴 것이다. 로그인 유저면 tenant 무관하게 동일한 값을 본다.")
    @GetMapping("/rules")
    public List<RuleCatalogEntryResponse> rules(
            @RequestHeader(name = "Authorization", required = false) String authorization) {
        auth.resolve(bearerToken(authorization));   // 로그인 여부만 확인. 정적 참조 데이터라 tenant 격리는 없다
        return ThreatCatalog.all().stream()
                .map(e -> new RuleCatalogEntryResponse(e.ruleId(), e.threatName(), e.category(), e.mitre(), e.description()))
                .toList();
    }

    private static String bearerToken(String authorization) {
        if (authorization == null || !authorization.startsWith(BEARER_PREFIX)) {
            return null;
        }
        return authorization.substring(BEARER_PREFIX.length()).trim();
    }

    public record RuleCatalogEntryResponse(
            String ruleId, String threatName, String category, String mitre, String description) {
    }
}
