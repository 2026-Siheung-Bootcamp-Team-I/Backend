package com.edrdog.apiservice.event.web;

import com.edrdog.apiservice.auth.AuthException;
import com.edrdog.apiservice.auth.AuthService;
import com.edrdog.apiservice.auth.Principal;
import com.edrdog.apiservice.clickhouse.ClickHouseReader;
import com.edrdog.apiservice.event.EventResponse;
import com.edrdog.apiservice.query.EventQueryBuilder;
import com.edrdog.apiservice.web.PageHeaders;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
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
                    + "detail(타입별 부가정보) 은 named 필드로 펴서 주고, 원본 JSON 문자열도 detail 에 같이 준다.\n\n"
                    + "페이지네이션: offset 으로 건너뛴다(기본 0, 상한 " + EventQueryBuilder.MAX_OFFSET + "). "
                    + "상한을 넘으면 400 이며, 더 깊이 파야 하면 offset 을 키우는 대신 from/to 로 범위를 좁혀라 "
                    + "(ClickHouse 의 OFFSET 은 건너뛸 행을 실제로 읽는다). "
                    + "응답 본문은 지금과 같은 배열이고 페이지 정보는 헤더로 나간다: "
                    + "X-Has-More(다음 페이지 유무), X-Time-From/X-Time-To(이 응답에 실제로 적용된 시간 범위), "
                    + "withTotal=true 일 때만 X-Total-Count(전체 건수).\n\n"
                    + "**다음 페이지를 부를 때는 첫 응답의 X-Time-To 를 to 에 그대로 실어야 한다.** "
                    + "조회가 최신순이라 그사이 새 이벤트가 맨 위에 쌓이면 offset 이 밀려서 행이 겹치거나 건너뛰어진다. "
                    + "to 를 안 주면 서버가 요청 시각으로 고정해 적용하고 그 값을 X-Time-To 로 알려 준다.")
    @GetMapping("/events")
    public ResponseEntity<List<EventResponse>> events(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @RequestParam(required = false) String host,
            @RequestParam(required = false) String type,
            @RequestParam(required = false) String sha256,
            @RequestParam(required = false) Long from,
            @RequestParam(required = false) Long to,
            @RequestParam(required = false) Integer limit,
            @RequestParam(required = false) Integer offset,
            @RequestParam(required = false, defaultValue = "false") boolean withTotal) {
        requireValidOffset(offset);
        // to 를 안 준 첫 페이지를 여기서 고정해야 다음 페이지가 같은 범위를 볼 수 있다.
        long resolvedTo = to != null ? to : System.currentTimeMillis();
        String tenantId = currentTenantId(authorization);
        int size = EventQueryBuilder.pageSize(limit);
        List<Map<String, Object>> rows = reader.query(
                builder.eventsPage(tenantId, host, type, sha256, from, resolvedTo, limit, offset));
        boolean hasMore = rows.size() > size;
        List<EventResponse> items = (hasMore ? rows.subList(0, size) : rows).stream()
                .map(row -> EventResponse.fromRow(row, mapper))
                .toList();
        // 같은 WHERE 로 count() 를 한 번 더 도는 것이라 화면이 명시적으로 요청할 때만 센다.
        Long total = withTotal ? countEvents(tenantId, host, type, sha256, from, resolvedTo) : null;
        return PageHeaders.body(items, hasMore, total, from != null ? from : 0L, resolvedTo);
    }

    /** 같은 필터·같은 tenant 로 총 건수를 센다. tenant 를 빼면 남의 조직 건수가 총계에 섞여 그 자체로 정보가 샌다. */
    private long countEvents(String tenantId, String host, String type, String sha256, Long from, Long to) {
        List<Map<String, Object>> rows = reader.query(builder.countEvents(tenantId, host, type, sha256, from, to));
        return rows.isEmpty() ? 0L : Long.parseLong(String.valueOf(rows.get(0).get("cnt")));
    }

    /** 상한을 넘은 offset 은 조용히 자르지 않고 400 으로 거절한다(자르면 화면이 빈 페이지로 읽는다). */
    private static void requireValidOffset(Integer offset) {
        if (offset != null && (offset < 0 || offset > EventQueryBuilder.MAX_OFFSET)) {
            throw AuthException.invalidInput("offset 은 0.." + EventQueryBuilder.MAX_OFFSET + " 여야 합니다: " + offset);
        }
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
        // 같은 host 의 같은 밀리초에 이벤트가 여럿일 수 있다. id 로 안 거르면 조작된 링크가 다른 이벤트를 연다.
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
