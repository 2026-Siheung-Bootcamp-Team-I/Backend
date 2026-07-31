package com.edrdog.apiservice.incident;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

/**
 * 사건의 결정적 id 생성(순수). 사건 본체 테이블이 없어 조회할 때마다 알림을 다시 묶으므로,
 * 같은 묶음이면 언제 조회해도 같은 id 가 나와야 트리아지 오버레이가 그대로 붙어 있는다.
 *
 * <p><b>씨앗은 묶음에서 가장 먼저 일어난 알림의 id 다</b>(같은 ts 면 알림 id 가 작은 쪽).
 * 후보를 이렇게 골랐다:
 * <ul>
 *   <li>알림 집합 전체를 접기 — 알림이 하나 붙는 순간 id 가 바뀌어 트리아지가 떨어져 나간다. 탈락.</li>
 *   <li>계보의 뿌리 프로세스 — 실제 호스트에서는 거의 모든 체인이 explorer.exe/launchd 한 뿌리로
 *       올라가서 서로 다른 사건이 같은 id 를 받는다. 탈락.</li>
 *   <li>가장 먼저 일어난 알림 — 사건은 시간이 지나며 뒤로 자라므로(체인 아래쪽에 알림이 붙는다)
 *       최초 알림은 그대로다. 채택.</li>
 * </ul>
 *
 * <p>남는 위험은 하나다. 더 이른 시각의 알림이 뒤늦게 도착해 같은 사건에 붙으면 씨앗이 바뀌어
 * 트리아지가 풀린다. 본체 테이블 없이 조회 시 계산하기로 한 선택의 잔여 비용이고, 대신 늦게 온
 * 알림이 미리 만들어 둔 사건과 어긋나는 문제와 그 정합성 코드가 통째로 없다.
 */
public final class IncidentId {

    private IncidentId() {
    }

    public static String of(String tenantId, String host, String firstAlertId) {
        String seed = tenantId + "|" + host + "|" + firstAlertId;
        return UUID.nameUUIDFromBytes(seed.getBytes(StandardCharsets.UTF_8)).toString();
    }
}
