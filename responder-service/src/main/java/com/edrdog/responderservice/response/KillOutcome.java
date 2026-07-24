package com.edrdog.responderservice.response;

import com.edrdog.responderservice.fleet.FleetScriptResult;

/**
 * Fleet 스크립트 실행 결과를 조치 결과로 해석하는 순수 로직.
 */
public enum KillOutcome {
    /** 일치 프로세스를 kill 함. */
    KILLED,
    /** 일치 프로세스가 없어 아무것도 안 함(이미 종료 등). */
    NO_MATCH,
    /** 호스트 오프라인/제한시간 초과로 실행 확인 못 함. */
    TIMEOUT,
    /** 스크립트가 실패했거나 예상치 못한 출력. */
    FAILED;

    private static final String MARK_KILLED = "EDRDOG_RESULT=KILLED";
    private static final String MARK_NO_MATCH = "EDRDOG_RESULT=NO_MATCH";

    public static KillOutcome interpret(FleetScriptResult r) {
        if (r.hostTimeout() || r.exitCode() == null) {
            return TIMEOUT;
        }
        if (r.exitCode() != 0) {
            return FAILED;
        }
        String out = r.output() == null ? "" : r.output();
        if (out.contains(MARK_KILLED)) {
            return KILLED;
        }
        if (out.contains(MARK_NO_MATCH)) {
            return NO_MATCH;
        }
        return FAILED;
    }
}
