package com.edrdog.apiservice.demo.web;

import com.edrdog.apiservice.alert.web.AlertResponse;
import com.edrdog.apiservice.demo.CollectedEvent;

import java.util.List;

/**
 * 데모 수집 API 응답. 한 번의 호출로 "엔드포인트 로그 발행 → 판정 → 저장" 전 구간을 담는다.
 *
 * @param scenario       실행한 시나리오 이름
 * @param host           로그를 보낸 것으로 꾸민 엔드포인트
 * @param tenantId       조직(tenant) 식별자
 * @param pipeline       지나간 경로 한 줄 요약 (발표 슬라이드와 대조용)
 * @param alertId        기대한 alert id — 발행 전에 결정되므로 조회 API 에 그대로 넣어볼 수 있다
 * @param totalElapsedMs 전체 소요 시간
 * @param steps          단계별 결과
 * @param collectedLogs  발행한 이벤트 원본 (수집된 로그 그 자체)
 * @param alert          저장까지 끝난 판정 결과. 아직 안 왔으면 null
 * @param nextSteps      발표에서 이어서 눌러볼 API 안내
 */
public record DemoFlowResponse(
        String scenario,
        String host,
        String tenantId,
        String pipeline,
        String alertId,
        long totalElapsedMs,
        List<DemoFlowStep> steps,
        List<CollectedEvent> collectedLogs,
        AlertResponse alert,
        List<String> nextSteps
) {
}
