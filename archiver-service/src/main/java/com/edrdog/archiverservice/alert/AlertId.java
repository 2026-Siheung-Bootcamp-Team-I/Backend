package com.edrdog.archiverservice.alert;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

/** alert 의 결정적 id 생성(순수). tenantId|host|ruleId|ts 를 UUID v3(name-based)로 접어 만든다. 같은 판정이 재소비돼도 같은 id 라 멱등 적재가 성립한다. */
// api-service 에 같은 사본이 있다. 한쪽 씨앗만 바꾸면 적재한 id 와 조회하는 id 가 어긋나고 컴파일러는 모른다. 이를 잡는 건 양쪽 AlertIdTest 의 고정값뿐이다.
public final class AlertId {

    private AlertId() {
    }

    public static String of(String tenantId, String host, String ruleId, long ts) {
        String seed = tenantId + "|" + host + "|" + ruleId + "|" + ts;
        return UUID.nameUUIDFromBytes(seed.getBytes(StandardCharsets.UTF_8)).toString();
    }
}
