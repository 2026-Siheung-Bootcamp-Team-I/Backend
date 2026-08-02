package com.edrdog.alertservice;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 키별 마지막 발송 시각을 기억해 윈도우 안 중복 발송을 억제하는 순수 로직 (Slack 스팸 방지).
 * 시각(nowMs)은 호출자가 주입한다 (벽시계 대신 alert 이벤트 시각 사용 → 결정적).
 */
public class Cooldown {

    private final long windowMs;
    // 컨슈머 concurrency 를 올려도 안전해야 하므로 ConcurrentHashMap 이다.
    private final Map<String, Long> lastSent = new ConcurrentHashMap<>();

    public Cooldown(long windowMs) {
        this.windowMs = windowMs;
    }

    /** 키가 윈도우 밖이면 통과시키고 시각을 갱신, 윈도우 안이면 억제. */
    public boolean allow(String key, long nowMs) {
        Long last = lastSent.get(key);
        if (last != null && nowMs - last < windowMs) {
            return false;
        }
        lastSent.put(key, nowMs);
        return true;
    }

    /** 기록을 지워 다음 요청이 다시 통과하게 한다. 실패한 발송이 쿨다운 창을 태우는 것을 막는다. */
    public void forget(String key) {
        lastSent.remove(key);
    }
}
