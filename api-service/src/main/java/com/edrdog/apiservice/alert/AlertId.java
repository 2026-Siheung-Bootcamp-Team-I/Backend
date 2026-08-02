package com.edrdog.apiservice.alert;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

/** alert 의 결정적 id 생성(순수). tenantId|host|ruleId|ts 를 UUID v3(name-based)로 접어 만든다. */
// 씨앗 구성이나 순서를 바꾸면 같은 판정이 다른 id 를 받아 재소비 시 멱등 적재가 깨진다.
public final class AlertId {

    private AlertId() {
    }

    public static String of(String tenantId, String host, String ruleId, long ts) {
        String seed = tenantId + "|" + host + "|" + ruleId + "|" + ts;
        return UUID.nameUUIDFromBytes(seed.getBytes(StandardCharsets.UTF_8)).toString();
    }
}
