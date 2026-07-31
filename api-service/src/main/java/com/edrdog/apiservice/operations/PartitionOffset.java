package com.edrdog.apiservice.operations;

/**
 * 파티션 하나의 끝 오프셋(latest)과 컨슈머 그룹의 커밋 오프셋.
 * committedOffset 이 null 이면 그 파티션은 그룹이 아직 커밋한 적이 없다는 뜻이다(모름과 0을 구분).
 */
public record PartitionOffset(int partition, long endOffset, Long committedOffset) {
}
