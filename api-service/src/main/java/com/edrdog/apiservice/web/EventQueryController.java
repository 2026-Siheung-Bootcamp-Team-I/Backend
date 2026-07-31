package com.edrdog.apiservice.web;

import com.edrdog.apiservice.auth.exception.AuthException;
import com.edrdog.apiservice.auth.service.AuthService;
import com.edrdog.apiservice.auth.service.Principal;
import com.edrdog.apiservice.clickhouse.ClickHouseReader;
import com.edrdog.apiservice.query.EventQueryBuilder;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * ClickHouse(edrdog.events) 조회·요약을 프론트에 제공하는 읽기 전용 REST.
 * 모든 요청은 세션 Bearer 토큰으로 인증하고, 그 토큰의 tenant 로만 조회를 격리한다("A사는 A사 것만").
 */
@RestController
@RequestMapping("/api")
@Tag(name = "events", description = "이벤트 조회 및 요약 (ClickHouse, tenant 격리)")
public class EventQueryController {

    private static final String BEARER_PREFIX = "Bearer ";

    private final ClickHouseReader reader;
    private final EventQueryBuilder builder;
    private final AuthService auth;
    private final ObjectMapper mapper;

    public EventQueryController(ClickHouseReader reader, EventQueryBuilder builder, AuthService auth,
                                 ObjectMapper mapper) {
        this.reader = reader;
        this.builder = builder;
        this.auth = auth;
        this.mapper = mapper;
    }

    @Operation(summary = "이벤트 조회",
            description = "로그인 유저의 tenant 것만 host/type/sha256/from/to(epoch millis) 필터로 최신순 조회. "
                    + "sha256 은 파일 해시 완전일치이며 대소문자를 가리지 않는다. limit 기본 100, 상한 1000. "
                    + "detail(타입별 부가정보) 은 named 필드로 펴서 주고, 원본 JSON 문자열도 detail 에 같이 준다.")
    @GetMapping("/events")
    public List<EventResponse> events(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @RequestParam(required = false) String host,
            @RequestParam(required = false) String type,
            @RequestParam(required = false) String sha256,
            @RequestParam(required = false) Long from,
            @RequestParam(required = false) Long to,
            @RequestParam(required = false) Integer limit) {
        String tenantId = currentTenantId(authorization);
        List<Map<String, Object>> rows = reader.query(builder.events(tenantId, host, type, sha256, from, to, limit));
        return rows.stream().map(row -> EventResponse.fromRow(row, mapper)).toList();
    }

    @Operation(summary = "이벤트 단건 조회",
            description = "id 로 이벤트 하나를 지목해 연다(조사 화면 공유 링크). 응답은 목록과 같은 EventResponse 다. "
                    + "id 는 저장된 값이 아니라 이벤트 내용을 접어 만든 것이라 WHERE 로 못 거른다. 그래서 host 와 "
                    + "ts(epoch millis)를 필수로 받아 그 주변 좁은 범위만 조회하고, 그 안에서 id 가 일치하는 행만 준다. "
                    + "host/ts 가 없으면 400, id 가 안 맞거나 남의 tenant 것이면 404.")
    @GetMapping("/events/{id}")
    public EventResponse event(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @PathVariable String id,
            @RequestParam String host,
            @RequestParam Long ts) {
        String tenantId = currentTenantId(authorization);
        if (host.isBlank()) {
            throw AuthException.invalidInput("host 는 필수입니다");
        }
        List<Map<String, Object>> rows = reader.query(builder.eventAt(tenantId, host, ts));
        // 같은 host 의 같은 밀리초에 이벤트가 여럿일 수 있다. 창 안에서 시각으로 아무거나 고르는 대신
        // 행마다 id 를 다시 접어 정확히 일치하는 것만 고른다. 링크가 조작되면 다른 이벤트 대신 404 다.
        return rows.stream()
                .map(row -> EventResponse.fromRow(row, mapper))
                .filter(event -> event.id().equals(id))
                .findFirst()
                .orElseThrow(() -> AuthException.notFound("이벤트를 찾을 수 없습니다"));
    }

    @Operation(summary = "이벤트 요약",
            description = "로그인 유저의 tenant 것만 시간범위(from/to, epoch millis) 안에서 type 별 건수로 집계하고 총합을 함께 준다.")
    @GetMapping("/events/summary")
    public Map<String, Object> summary(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @RequestParam(required = false) Long from,
            @RequestParam(required = false) Long to) {
        String tenantId = currentTenantId(authorization);
        List<Map<String, Object>> byType = reader.query(builder.summaryByType(tenantId, from, to));
        long total = byType.stream()
                .mapToLong(row -> Long.parseLong(String.valueOf(row.get("cnt"))))
                .sum();
        return Map.of("total", total, "byType", byType);
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
