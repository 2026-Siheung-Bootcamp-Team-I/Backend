package com.edrdog.apiservice.incident;

import java.util.List;
import java.util.Map;

/**
 * 계보로 묶인 알림 한 덩어리. 저장하지 않고 조회할 때 계산하는 값이라 엔티티가 아니다.
 *
 * @param alerts      구성 알림(판정기록 ClickHouse 행). 시간 오름차순이고 첫 행이 id 의 씨앗이다.
 * @param rootProcess 체인에서 가장 위에 있는 알림의 프로세스명. 못 찾았으면 빈 문자열이다.
 * @param chainNodes  사건에 속한 프로세스 노드 id 들(LineageGraphBuilder 규칙). 타임라인·그래프가 이걸로 이벤트를 고른다.
 */
public record Incident(
        String id,
        String host,
        long firstTs,
        long lastTs,
        String severity,
        String rootProcess,
        List<Map<String, Object>> alerts,
        List<String> chainNodes
) {
}
