package com.edrdog.apiservice.operations;

import org.junit.jupiter.api.Test;
import org.springframework.boot.actuate.health.Health;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * 의존 저장소 도달 여부 판단(순수 로직) 검증.
 * Kafka/ClickHouse 는 actuator 헬스 인디케이터가 없어 lag/적재지연 조회 결과 자체로 판단한다.
 */
class DependencyStatusesTest {

    // --- kafka ---

    @Test
    void 하나라도_성공하면_kafka는_up() {
        List<KafkaTopicLagResult> lags = List.of(
                KafkaTopicLagResult.of("alerts", "api-demo-arrivals", 5L),
                KafkaTopicLagResult.error("events", "detector", "timeout"));
        DependencyResult result = DependencyStatuses.kafka(lags);
        assertEquals("up", result.status());
        assertNull(result.error());
    }

    @Test
    void 전부_실패하면_kafka는_down_이고_첫_에러를_담는다() {
        List<KafkaTopicLagResult> lags = List.of(
                KafkaTopicLagResult.error("alerts", "api-demo-arrivals", "broker unreachable"),
                KafkaTopicLagResult.error("events", "detector", "timeout"));
        DependencyResult result = DependencyStatuses.kafka(lags);
        assertEquals("down", result.status());
        assertEquals("broker unreachable", result.error());
    }

    // --- clickhouse ---

    @Test
    void 하나라도_성공하면_clickhouse는_up() {
        List<ClickHouseIngestionResult> results = List.of(
                ClickHouseIngestionResult.error("edrdog.events", "connection refused"),
                ClickHouseIngestionResult.of("edrdog.alerts", 3L, 10));
        assertEquals("up", DependencyStatuses.clickhouse(results).status());
    }

    @Test
    void 전부_실패하면_clickhouse는_down() {
        List<ClickHouseIngestionResult> results = List.of(
                ClickHouseIngestionResult.error("edrdog.events", "connection refused"),
                ClickHouseIngestionResult.error("edrdog.alerts", "connection refused"));
        DependencyResult result = DependencyStatuses.clickhouse(results);
        assertEquals("down", result.status());
        assertEquals("connection refused", result.error());
    }

    // --- db ---

    @Test
    void db_헬스가_없으면_모름() {
        DependencyResult result = DependencyStatuses.db(null);
        assertEquals("unknown", result.status());
    }

    @Test
    void db_헬스가_UP이면_up() {
        assertEquals("up", DependencyStatuses.db(Health.up().build()).status());
    }

    @Test
    void db_헬스가_DOWN이면_down() {
        assertEquals("down", DependencyStatuses.db(Health.down().build()).status());
    }

    @Test
    void db_헬스가_UNKNOWN이면_모름() {
        assertEquals("unknown", DependencyStatuses.db(Health.unknown().build()).status());
    }
}
