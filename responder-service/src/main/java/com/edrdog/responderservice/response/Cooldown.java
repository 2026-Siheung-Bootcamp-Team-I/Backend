package com.edrdog.responderservice.response;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 키별 마지막 표시 시각을 기억해 윈도우 안 중복 표시를 억제하는 순수 로직.
 * 시각(nowMs)은 호출자가 주입한다 (벽시계 대신 alert 이벤트 시각 사용 → 결정적).
 */
public class Cooldown {

    private final long windowMs;
    // 여러 HTTP 스레드가 동시에 allow 를 부르므로 ConcurrentHashMap 이다.
    private final Map<String, Long> lastShown = new ConcurrentHashMap<>();

    public Cooldown(long windowMs) {
        this.windowMs = windowMs;
    }

    /** 키가 윈도우 밖이면 통과시키고 시각을 갱신, 윈도우 안이면 억제. */
    public boolean allow(String key, long nowMs) {
        boolean[] allowed = new boolean[1];
        // 판정과 갱신은 compute 로 한 번에 한다. get 후 put 으로 쪼개면 두 스레드가 같이 통과한다.
        lastShown.compute(key, (k, last) -> {
            // 경계는 < 다. <= 로 바꾸면 정확히 windowMs 만큼 뒤에 온 요청까지 억제된다.
            if (last != null && nowMs - last < windowMs) {
                return last;
            }
            allowed[0] = true;
            return nowMs;
        });
        return allowed[0];
    }
}
