package com.edrdog.responderservice.response;

import com.edrdog.responderservice.fleet.FleetClient;
import com.edrdog.responderservice.fleet.FleetScriptResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * 실제 조치(프로세스 kill)를 Fleet run-script 로 실행하는 반자동 실행기.
 *
 * 안전장치:
 * - enabled 기본 false → 켜기 전엔 실제 실행 안 함(dry-run 유지).
 * - 사람이 트리거(대시보드 버튼 → API)해야 실행 → 오탐 리스크는 사람이 차단.
 * - host 단위 쿨다운 → 동일 호스트 재조치/폭주 차단(무한 루프 2차 방어).
 * - trigger=response 태깅 → 이 조치가 만든 이벤트는 판정에서 제외(무한 루프 1차 방어).
 */
@Service
public class ResponseExecutor {

    private static final Logger log = LoggerFactory.getLogger(ResponseExecutor.class);

    private final FleetClient fleet;
    private final boolean enabled;
    private final Cooldown cooldown;

    public ResponseExecutor(FleetClient fleet,
                            @Value("${edrdog.responder.execute.enabled}") boolean enabled,
                            @Value("${edrdog.responder.cooldown-ms}") long cooldownMs) {
        this.fleet = fleet;
        this.enabled = enabled;
        this.cooldown = new Cooldown(cooldownMs);
    }

    /** host 의 target 프로세스를 kill. 실행 스위치·쿨다운을 통과할 때만 Fleet 을 호출한다. */
    public ExecuteResult killProcess(String host, String target) {
        if (!enabled) {
            log.info("[EXECUTE-DISABLED] trigger=response host={} target={} (실행 스위치 꺼짐, 아무것도 안 함)", host, target);
            return new ExecuteResult(host, target, "DISABLED", null);
        }
        if (!cooldown.allow(host, System.currentTimeMillis())) {
            log.info("[EXECUTE-COOLDOWN] trigger=response host={} target={} (쿨다운, 재조치 억제)", host, target);
            return new ExecuteResult(host, target, "COOLDOWN", null);
        }
        try {
            int hostId = fleet.resolveHostId(host);
            FleetScriptResult result = fleet.runScriptSync(hostId, KillScript.build(target));
            KillOutcome outcome = KillOutcome.interpret(result);
            log.info("[EXECUTE] trigger=response host={} target={} outcome={} execId={}",
                    host, target, outcome, result.executionId());
            return new ExecuteResult(host, target, outcome.name(), result.executionId());
        } catch (Exception e) {
            log.error("[EXECUTE-FAILED] trigger=response host={} target={} err={}", host, target, e.toString());
            return new ExecuteResult(host, target, "FAILED", null);
        }
    }
}
