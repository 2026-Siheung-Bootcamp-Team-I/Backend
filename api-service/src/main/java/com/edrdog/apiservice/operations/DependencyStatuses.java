package com.edrdog.apiservice.operations;

import org.springframework.boot.actuate.health.HealthComponent;
import org.springframework.boot.actuate.health.Status;

import java.util.List;

/**
 * 의존 저장소(Kafka/ClickHouse/MySQL) 도달 여부를 판단하는 순수 로직.
 *
 * <p>MySQL 은 actuator 의 DataSourceHealthIndicator("db")가 이미 확인해 둔 걸 그대로 옮긴다.
 * Kafka/ClickHouse 는 이 프로젝트에 등록된 actuator 헬스 인디케이터가 없어서(직접 확인함),
 * 상태 화면이 어차피 수행하는 lag/적재지연 조회의 성공·실패를 그대로 재사용한다 — 도달 여부만
 * 확인하려고 별도 핑을 새로 날리지 않는다.
 */
final class DependencyStatuses {

    private DependencyStatuses() {
    }

    static DependencyResult kafka(List<KafkaTopicLagResult> lags) {
        if (lags.stream().anyMatch(r -> r.error() == null)) {
            return DependencyResult.up("kafka");
        }
        return DependencyResult.down("kafka", firstError(lags.stream().map(KafkaTopicLagResult::error).toList()));
    }

    static DependencyResult clickhouse(List<ClickHouseIngestionResult> results) {
        if (results.stream().anyMatch(r -> r.error() == null)) {
            return DependencyResult.up("clickhouse");
        }
        return DependencyResult.down("clickhouse",
                firstError(results.stream().map(ClickHouseIngestionResult::error).toList()));
    }

    static DependencyResult db(HealthComponent health) {
        if (health == null) {
            return DependencyResult.unknown("mysql", "db 헬스 인디케이터가 등록되지 않음");
        }
        Status status = health.getStatus();
        if (Status.UP.equals(status)) {
            return DependencyResult.up("mysql");
        }
        if (Status.UNKNOWN.equals(status)) {
            return DependencyResult.unknown("mysql", null);
        }
        return DependencyResult.down("mysql", status.getCode());
    }

    private static String firstError(List<String> errors) {
        return errors.stream().filter(e -> e != null).findFirst().orElse(null);
    }
}
