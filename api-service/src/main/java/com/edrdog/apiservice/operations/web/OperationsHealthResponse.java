package com.edrdog.apiservice.operations.web;

import com.edrdog.apiservice.operations.ClickHouseIngestionResult;
import com.edrdog.apiservice.operations.DependencyResult;
import com.edrdog.apiservice.operations.KafkaTopicLagResult;

import java.util.List;

/**
 * 파이프라인 상태 화면 응답. tenant 격리 없이 전체 운영 지표를 그대로 준다.
 * checkedAt 은 이 응답을 만든 시각(epoch millis)이고, 화면이 "몇 초 전 값인지" 표시하는 데 쓴다.
 */
public record OperationsHealthResponse(
        List<KafkaTopicLagResult> kafkaLag,
        List<ClickHouseIngestionResult> clickhouseIngestion,
        List<DependencyResult> dependencies,
        long checkedAt) {
}
