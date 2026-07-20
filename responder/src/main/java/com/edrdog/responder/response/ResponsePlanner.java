package com.edrdog.responder.response;

import com.edrdog.responder.dto.Alert;

import java.util.Optional;

/**
 * alert 의 권고 action 을 사람이 읽을 dry-run 조치 텍스트로 변환하는 순수 로직.
 * 실제 실행은 하지 않으며(표시만), host+action 단위로 쿨다운을 적용한다.
 */
public class ResponsePlanner {

    private final Cooldown cooldown;

    public ResponsePlanner(long cooldownMs) {
        this.cooldown = new Cooldown(cooldownMs);
    }

    /** 쿨다운을 통과하면 dry-run 표시 줄을 반환, 억제되거나 입력이 불완전하면 비어 있음. */
    public Optional<String> plan(Alert alert) {
        if (alert == null || alert.host() == null || alert.action() == null) {
            return Optional.empty();
        }
        String key = alert.host() + "|" + alert.action();
        if (!cooldown.allow(key, alert.ts())) {
            return Optional.empty();
        }
        return Optional.of(format(alert));
    }

    /** action → 권장 조치 텍스트. 알 수 없는 action 은 알림으로 처리. */
    static String label(String action) {
        return switch (action) {
            case Alert.ACTION_KILL -> "프로세스 종료 권장";
            case Alert.ACTION_ISOLATE -> "호스트 격리 권장";
            default -> "알림 권장";
        };
    }

    /** trigger=response 로 태깅된 dry-run 한 줄. 실제 실행은 없음을 명시. */
    static String format(Alert alert) {
        return String.format("[DRY-RUN] trigger=response host=%s rule=%s action=%s → %s (실행 안 함)",
                alert.host(), alert.ruleId(), alert.action(), label(alert.action()));
    }
}
