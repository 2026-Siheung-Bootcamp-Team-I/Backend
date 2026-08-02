package com.edrdog.apiservice.incident;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

/**
 * 사건의 결정적 id 생성(순수). <b>씨앗은 묶음에서 가장 먼저 일어난 알림의 id 다</b>(같은 ts 면 알림 id 가 작은 쪽).
 * 같은 묶음이면 언제 조회해도 같은 id 가 나와야 트리아지 오버레이가 그대로 붙어 있는다.
 */
public final class IncidentId {

    private IncidentId() {
    }

    public static String of(String tenantId, String host, String firstAlertId) {
        String seed = tenantId + "|" + host + "|" + firstAlertId;
        return UUID.nameUUIDFromBytes(seed.getBytes(StandardCharsets.UTF_8)).toString();
    }
}
