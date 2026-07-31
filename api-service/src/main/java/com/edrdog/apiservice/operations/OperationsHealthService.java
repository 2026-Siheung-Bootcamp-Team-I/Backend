package com.edrdog.apiservice.operations;

import com.edrdog.apiservice.operations.web.OperationsHealthResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.health.HealthComponent;
import org.springframework.boot.actuate.health.HealthEndpoint;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * 파이프라인 상태 화면(operations/health) 데이터를 모은다.
 * Kafka/ClickHouse 조회는 inspector 내부에서 이미 예외를 삼키고 error 로 감싸므로, 여기서는 조립만
 * 한다 — 항목 하나(가령 Kafka)가 죽어 있어도 나머지(ClickHouse/MySQL) 결과는 그대로 나가야 한다.
 */
@Service
public class OperationsHealthService {

    private final KafkaLagInspector kafkaLagInspector;
    private final ClickHouseIngestionInspector ingestionInspector;
    private final HealthEndpoint healthEndpoint;

    private final String alertsTopic;
    private final String eventsRawTopic;
    private final String eventsTopic;
    // 토픽 하나를 여러 그룹이 각자 소비할 수 있어(events 는 detector+archiver) 그룹은 목록이다.
    private final List<String> alertsConsumerGroups;
    private final List<String> eventsRawConsumerGroups;
    private final List<String> eventsConsumerGroups;
    private final String eventsTable;
    private final String alertsTable;

    public OperationsHealthService(
            KafkaLagInspector kafkaLagInspector,
            ClickHouseIngestionInspector ingestionInspector,
            HealthEndpoint healthEndpoint,
            @Value("${edrdog.kafka.alerts-topic}") String alertsTopic,
            @Value("${edrdog.kafka.events-raw-topic}") String eventsRawTopic,
            @Value("${edrdog.kafka.events-topic}") String eventsTopic,
            @Value("${edrdog.kafka.alerts-consumer-groups}") String alertsConsumerGroups,
            @Value("${edrdog.kafka.events-raw-consumer-groups}") String eventsRawConsumerGroups,
            @Value("${edrdog.kafka.events-consumer-groups}") String eventsConsumerGroups,
            @Value("${edrdog.clickhouse.table}") String eventsTable,
            @Value("${edrdog.clickhouse.alerts-table}") String alertsTable) {
        this.kafkaLagInspector = kafkaLagInspector;
        this.ingestionInspector = ingestionInspector;
        this.healthEndpoint = healthEndpoint;
        this.alertsTopic = alertsTopic;
        this.eventsRawTopic = eventsRawTopic;
        this.eventsTopic = eventsTopic;
        this.alertsConsumerGroups = parseGroups(alertsConsumerGroups);
        this.eventsRawConsumerGroups = parseGroups(eventsRawConsumerGroups);
        this.eventsConsumerGroups = parseGroups(eventsConsumerGroups);
        this.eventsTable = eventsTable;
        this.alertsTable = alertsTable;
    }

    public OperationsHealthResponse health() {
        List<KafkaTopicLagResult> kafkaLag = new ArrayList<>();
        addLag(kafkaLag, alertsTopic, alertsConsumerGroups);
        addLag(kafkaLag, eventsRawTopic, eventsRawConsumerGroups);
        addLag(kafkaLag, eventsTopic, eventsConsumerGroups);

        List<ClickHouseIngestionResult> ingestion = List.of(
                ingestionInspector.check(eventsTable, "ingested_at"),
                ingestionInspector.check(alertsTable, "created_at"));

        List<DependencyResult> dependencies = List.of(
                DependencyStatuses.kafka(kafkaLag),
                DependencyStatuses.clickhouse(ingestion),
                DependencyStatuses.db(dbHealth()));

        return new OperationsHealthResponse(kafkaLag, ingestion, dependencies, Instant.now().toEpochMilli());
    }

    /** 토픽 하나를 소비하는 그룹마다 (토픽, 그룹) 쌍의 lag 을 따로 담는다 — 어느 소비자가 밀렸는지 구분하기 위함. */
    private void addLag(List<KafkaTopicLagResult> results, String topic, List<String> groups) {
        for (String group : groups) {
            results.add(kafkaLagInspector.lag(topic, group));
        }
    }

    /** actuator 의 DataSourceHealthIndicator("db")를 그대로 재사용한다. 없거나 조회 자체가 죽으면 null(모름 처리는 DependencyStatuses 가 한다). */
    private HealthComponent dbHealth() {
        try {
            return healthEndpoint.healthForPath("db");
        } catch (Exception e) {
            return null;
        }
    }

    /** CorsConfig.parseOrigins 와 동일 패턴(쉼표 구분, 앞뒤 공백 제거, 빈 항목 제외). */
    private static List<String> parseGroups(String raw) {
        return Arrays.stream(raw.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();
    }
}
