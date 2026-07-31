package com.edrdog.apiservice.operations;

import org.apache.kafka.clients.admin.Admin;
import org.apache.kafka.clients.admin.OffsetSpec;
import org.apache.kafka.clients.admin.TopicDescription;
import org.apache.kafka.clients.consumer.OffsetAndMetadata;
import org.apache.kafka.common.TopicPartition;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * AdminClient 로 토픽 하나의 컨슈머 lag 을 구한다(끝 오프셋 - 커밋 오프셋).
 * 브로커가 죽어 있거나 그룹/토픽이 없어도 예외를 던지지 않고 KafkaTopicLagResult.error 로 감싼다
 * — 상태 화면 API 는 조회 하나가 실패해도 전체가 500이 되면 안 된다.
 */
@Component
public class KafkaLagInspector {

    // 상태 화면 응답을 오래 붙잡지 않도록 브로커 왕복마다 짧게 자른다.
    private static final Duration TIMEOUT = Duration.ofSeconds(5);

    private final Admin adminClient;

    public KafkaLagInspector(Admin adminClient) {
        this.adminClient = adminClient;
    }

    public KafkaTopicLagResult lag(String topic, String consumerGroup) {
        try {
            List<TopicPartition> partitions = describePartitions(topic);
            Map<TopicPartition, Long> endOffsets = endOffsets(partitions);
            Map<TopicPartition, Long> committed = committedOffsets(consumerGroup, partitions);
            List<PartitionOffset> offsets = partitions.stream()
                    .map(tp -> new PartitionOffset(tp.partition(), endOffsets.get(tp), committed.get(tp)))
                    .toList();
            return KafkaTopicLagResult.of(topic, consumerGroup, KafkaLagCalculator.totalLag(offsets));
        } catch (Exception e) {
            return KafkaTopicLagResult.error(topic, consumerGroup, e.getMessage());
        }
    }

    private List<TopicPartition> describePartitions(String topic) throws Exception {
        TopicDescription description = adminClient.describeTopics(List.of(topic))
                .topicNameValues().get(topic)
                .get(TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
        return description.partitions().stream()
                .map(p -> new TopicPartition(topic, p.partition()))
                .toList();
    }

    private Map<TopicPartition, Long> endOffsets(List<TopicPartition> partitions) throws Exception {
        Map<TopicPartition, OffsetSpec> specs = partitions.stream()
                .collect(Collectors.toMap(tp -> tp, tp -> OffsetSpec.latest()));
        return adminClient.listOffsets(specs).all()
                .get(TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)
                .entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, e -> e.getValue().offset()));
    }

    /** 그룹이 해당 파티션을 아직 커밋한 적 없으면 결과 맵에 키 자체가 없다(모름 처리는 호출부에서). */
    private Map<TopicPartition, Long> committedOffsets(String consumerGroup, List<TopicPartition> partitions)
            throws Exception {
        Map<TopicPartition, OffsetAndMetadata> committed = adminClient.listConsumerGroupOffsets(consumerGroup)
                .partitionsToOffsetAndMetadata()
                .get(TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
        return partitions.stream()
                .filter(tp -> committed.get(tp) != null)
                .collect(Collectors.toMap(tp -> tp, tp -> committed.get(tp).offset()));
    }
}
