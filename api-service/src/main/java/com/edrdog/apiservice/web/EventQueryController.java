package com.edrdog.apiservice.web;

import com.edrdog.apiservice.clickhouse.ClickHouseReader;
import com.edrdog.apiservice.query.EventQueryBuilder;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * ClickHouse(edrdog.events) 조회·요약을 프론트에 제공하는 읽기 전용 REST.
 * 모든 요청은 X-API-Key 인증(ApiKeyFilter) 뒤에서 처리된다.
 */
@RestController
@RequestMapping("/api")
@Tag(name = "events", description = "이벤트 조회 및 요약 (ClickHouse)")
public class EventQueryController {

    private final ClickHouseReader reader;
    private final EventQueryBuilder builder;

    public EventQueryController(ClickHouseReader reader, EventQueryBuilder builder) {
        this.reader = reader;
        this.builder = builder;
    }

    @Operation(summary = "이벤트 조회",
            description = "host/type/from/to(epoch millis) 필터로 최신순 조회. limit 기본 100, 상한 1000.")
    @GetMapping("/events")
    public List<Map<String, Object>> events(
            @RequestParam(required = false) String host,
            @RequestParam(required = false) String type,
            @RequestParam(required = false) Long from,
            @RequestParam(required = false) Long to,
            @RequestParam(required = false) Integer limit) {
        return reader.query(builder.events(host, type, from, to, limit));
    }

    @Operation(summary = "이벤트 요약",
            description = "시간범위(from/to, epoch millis) 안 이벤트를 type 별 건수로 집계하고 총합을 함께 준다.")
    @GetMapping("/events/summary")
    public Map<String, Object> summary(
            @RequestParam(required = false) Long from,
            @RequestParam(required = false) Long to) {
        List<Map<String, Object>> byType = reader.query(builder.summaryByType(from, to));
        long total = byType.stream()
                .mapToLong(row -> Long.parseLong(String.valueOf(row.get("cnt"))))
                .sum();
        return Map.of("total", total, "byType", byType);
    }
}
