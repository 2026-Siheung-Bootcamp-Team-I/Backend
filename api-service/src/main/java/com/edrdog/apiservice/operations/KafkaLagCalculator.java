package com.edrdog.apiservice.operations;

import java.util.List;

/**
 * lag = 파티션별(끝 오프셋 - 커밋 오프셋)의 합(순수 로직).
 * 커밋 오프셋을 못 구한 파티션이 하나라도 있으면 전체를 모름(null)으로 취급한다.
 * 여기서 0을 채우면 "지연 없음"으로 화면에 조용히 잘못 읽힌다.
 */
public final class KafkaLagCalculator {

    private KafkaLagCalculator() {
    }

    public static Long totalLag(List<PartitionOffset> partitions) {
        if (partitions.isEmpty()) {
            return null;
        }
        long total = 0;
        for (PartitionOffset p : partitions) {
            if (p.committedOffset() == null) {
                return null;
            }
            // 컨슈머가 끝 오프셋보다 앞서 커밋한 값을 볼 수도 있어(트랜잭션 마커 등) 음수는 0으로 클램프.
            total += Math.max(0, p.endOffset() - p.committedOffset());
        }
        return total;
    }
}
