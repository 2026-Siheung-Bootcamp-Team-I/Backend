package com.edrdog.apiservice.operations;

/**
 * 토픽 하나의 컨슈머 lag 조회 결과.
 * status: up(lag 계산됨) | unknown(파티션 일부가 커밋 이력 없어 못 구함) | down(AdminClient 조회 자체가 실패).
 * lag 는 unknown/down 이면 null 이다(0으로 채워 "지연 없음"처럼 보이지 않게).
 */
public record KafkaTopicLagResult(String topic, String consumerGroup, Long lag, String status, String error) {

    public static KafkaTopicLagResult of(String topic, String consumerGroup, Long lag) {
        return new KafkaTopicLagResult(topic, consumerGroup, lag, lag == null ? "unknown" : "up", null);
    }

    public static KafkaTopicLagResult error(String topic, String consumerGroup, String error) {
        return new KafkaTopicLagResult(topic, consumerGroup, null, "down", error);
    }
}
