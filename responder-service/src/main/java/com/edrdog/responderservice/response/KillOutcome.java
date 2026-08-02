package com.edrdog.responderservice.response;

/**
 * 에이전트가 보고할 수 있는 조치 결과.
 *
 * <p>TIMEOUT / COOLDOWN / DISABLED 는 서버가 붙이는 상태라 여기 없다.
 */
public enum KillOutcome {
    /** 대상을 찾아 종료했다. */
    KILLED,
    /** 그 이름/경로로 도는 프로세스가 없다. */
    NO_MATCH,
    /** 찾았지만 종료하지 못했다. */
    FAILED;

    /**
     * 에이전트가 보고한 문자열을 알려진 상태로 해석한다. 모르는 값은 FAILED 다.
     * 이 해석을 빼고 값을 그대로 믿으면 임의의 문자열로 알림을 CONFIRMED 까지 밀어 올릴 수 있다.
     */
    public static KillOutcome of(String reported) {
        if (reported == null) {
            return FAILED;
        }
        for (KillOutcome outcome : values()) {
            if (outcome.name().equals(reported)) {
                return outcome;
            }
        }
        return FAILED;
    }
}
