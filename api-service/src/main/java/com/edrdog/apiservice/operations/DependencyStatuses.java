package com.edrdog.apiservice.operations;

import org.springframework.boot.actuate.health.HealthComponent;
import org.springframework.boot.actuate.health.Status;

import java.util.List;

/**
 * 의존 저장소(Kafka/ClickHouse/MySQL) 도달 여부를 판단하는 순수 로직.
 *
 * <p>Kafka/ClickHouse 는 별도 핑 대신 상태 화면이 어차피 수행하는 lag/적재지연 조회의 성공·실패를 재사용하고,
 * MySQL 은 actuator 의 DataSourceHealthIndicator("db") 결과를 그대로 옮긴다.
 *
 * <p>조회가 하나라도 성공하면 up 이다. 토픽·테이블 하나가 실패했다고 저장소 전체를 down 으로 내리면
 * 실제로는 붙어 있는 의존성이 죽은 것으로 보인다.
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
