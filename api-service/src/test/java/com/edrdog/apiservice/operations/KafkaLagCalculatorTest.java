package com.edrdog.apiservice.operations;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * lag 합산(순수 로직) 검증. 커밋 오프셋을 못 구한 파티션이 하나라도 있으면 전체를 모름(null)으로
 * 취급해야 한다 — 0으로 채우면 "지연 없음"으로 조용히 틀린 값이 나가기 때문이다.
 */
class KafkaLagCalculatorTest {

    @Test
    void 파티션이_없으면_모름() {
        assertNull(KafkaLagCalculator.totalLag(List.of()));
    }

    @Test
    void 모든_파티션에_커밋_오프셋이_있으면_차이의_합을_반환() {
        List<PartitionOffset> partitions = List.of(
                new PartitionOffset(0, 100L, 90L),
                new PartitionOffset(1, 200L, 150L));
        assertEquals(60L, KafkaLagCalculator.totalLag(partitions));
    }

    @Test
    void 한_파티션이라도_커밋_오프셋이_없으면_전체가_모름() {
        List<PartitionOffset> partitions = List.of(
                new PartitionOffset(0, 100L, 90L),
                new PartitionOffset(1, 200L, null));
        assertNull(KafkaLagCalculator.totalLag(partitions));
    }

    @Test
    void 커밋_오프셋이_끝_오프셋보다_앞서도_0으로_클램프() {
        // 트랜잭션 마커 등으로 커밋 값이 끝 오프셋을 넘어서는 경우가 있어도 음수 lag 는 내지 않는다.
        List<PartitionOffset> partitions = List.of(new PartitionOffset(0, 100L, 120L));
        assertEquals(0L, KafkaLagCalculator.totalLag(partitions));
    }

    @Test
    void 단일_파티션_lag_는_그대로() {
        List<PartitionOffset> partitions = List.of(new PartitionOffset(0, 500L, 500L));
        assertEquals(0L, KafkaLagCalculator.totalLag(partitions));
    }
}
