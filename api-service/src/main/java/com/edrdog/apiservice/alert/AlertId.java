package com.edrdog.apiservice.alert;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

/**
 * alert 의 결정적 id 생성(순수). tenantId|host|ruleId|ts 를 UUID v3(name-based)로 접어 만든다.
 * 같은 판정이 재소비돼도 같은 id 가 나와 멱등 적재가 성립한다.
 */
public final class AlertId {

    private AlertId() {
    }

    public static String of(String tenantId, String host, String ruleId, long ts) {
        String seed = tenantId + "|" + host + "|" + ruleId + "|" + ts;
        return UUID.nameUUIDFromBytes(seed.getBytes(StandardCharsets.UTF_8)).toString();
    }
}
