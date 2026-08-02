package com.edrdog.responderservice.response;

import com.edrdog.responderservice.command.CommandQueue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Optional;

/**
 * 실제 조치(프로세스 kill)를 명령 큐에 실어 보내고 결과를 기다리는 반자동 실행기.
 *
 * 안전장치. 넷 다 지우면 사고가 난다:
 * - enabled 기본 false → 켜기 전엔 실제 실행 안 함(dry-run 유지).
 * - 사람이 트리거(대시보드 버튼 → API)해야 실행 → 오탐 리스크는 사람이 차단.
 * - host 단위 쿨다운 → 동일 호스트 재조치/폭주 차단(무한 루프 2차 방어).
 * - trigger=response 태깅 → 이 조치가 만든 이벤트가 다시 판정에 걸려 무한 루프가 되는 것을 막는다(1차 방어).
 */
@Service
public class ResponseExecutor {

    private static final Logger log = LoggerFactory.getLogger(ResponseExecutor.class);

    private final CommandQueue commands;
    private final boolean enabled;
    private final Cooldown cooldown;
    private final Duration commandTimeout;

    public ResponseExecutor(CommandQueue commands,
                            @Value("${edrdog.responder.execute.enabled}") boolean enabled,
                            @Value("${edrdog.responder.cooldown-ms}") long cooldownMs,
                            @Value("${edrdog.responder.command.timeout-ms}") long commandTimeoutMs) {
        this.commands = commands;
        this.enabled = enabled;
        this.cooldown = new Cooldown(cooldownMs);
        this.commandTimeout = Duration.ofMillis(commandTimeoutMs);
    }

    /** host 의 target 프로세스를 kill. 실행 스위치·쿨다운을 통과할 때만 명령을 내려보낸다. */
    public ExecuteResult killProcess(String host, String target) {
        // 이 스위치를 지우면 켜기 전에 실제 kill 이 나간다. 기본값은 false 다.
        if (!enabled) {
            log.info("[EXECUTE-DISABLED] trigger=response host={} target={} (실행 스위치 꺼짐, 아무것도 안 함)", host, target);
            return new ExecuteResult(host, target, "DISABLED", null);
        }
        // 이 검사를 빼면 같은 호스트에 재조치가 연달아 나간다.
        if (!cooldown.allow(host, System.currentTimeMillis())) {
            log.info("[EXECUTE-COOLDOWN] trigger=response host={} target={} (쿨다운, 재조치 억제)", host, target);
            return new ExecuteResult(host, target, "COOLDOWN", null);
        }
        String commandId = null;
        try {
            commandId = commands.dispatch(host, "kill_process", target);
            Optional<String> reported = commands.awaitResult(commandId, commandTimeout);
            if (reported.isEmpty()) {
                log.info("[EXECUTE-TIMEOUT] trigger=response host={} target={} cmd={} (하트비트 안에 결과 없음)",
                        host, target, commandId);
                return new ExecuteResult(host, target, "TIMEOUT", commandId);
            }
            // 보고 문자열을 그대로 믿으면 임의의 값이 알림 상태를 밀어 올린다. 모르는 값은 FAILED 다.
            KillOutcome outcome = KillOutcome.of(reported.get());
            log.info("[EXECUTE] trigger=response host={} target={} outcome={} cmd={}",
                    host, target, outcome, commandId);
            return new ExecuteResult(host, target, outcome.name(), commandId);
        } catch (Exception e) {
            log.error("[EXECUTE-FAILED] trigger=response host={} target={} err={}", host, target, e.toString());
            return new ExecuteResult(host, target, "FAILED", commandId);
        }
    }
}
