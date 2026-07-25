package com.edrdog.apiservice.demo.web;

/**
 * 데모 플로우 한 단계의 결과. 발표에서 "지금 어디까지 갔는지" 를 그대로 읽어 보여주는 용도다.
 *
 * @param no        단계 번호 (1부터)
 * @param name      단계 이름 (수집 / 탐지 / 저장)
 * @param path      그 단계가 지나간 경로 (예: api-service → Kafka(events))
 * @param status    OK 또는 TIMEOUT
 * @param elapsedMs 앞 단계 끝난 시점부터 이 단계까지 걸린 시간
 * @param detail    사람이 읽을 설명 (무엇이 몇 건, 어떤 룰에 걸렸는지)
 */
public record DemoFlowStep(
        int no,
        String name,
        String path,
        String status,
        long elapsedMs,
        String detail
) {

    public static final String OK = "OK";
    public static final String TIMEOUT = "TIMEOUT";

    public static DemoFlowStep ok(int no, String name, String path, long elapsedMs, String detail) {
        return new DemoFlowStep(no, name, path, OK, elapsedMs, detail);
    }

    public static DemoFlowStep timeout(int no, String name, String path, long elapsedMs, String detail) {
        return new DemoFlowStep(no, name, path, TIMEOUT, elapsedMs, detail);
    }
}
