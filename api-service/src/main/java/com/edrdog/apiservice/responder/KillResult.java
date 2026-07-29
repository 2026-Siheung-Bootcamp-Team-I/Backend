package com.edrdog.apiservice.responder;

/**
 * responder-service kill 실행 결과(responder 의 ExecuteResult 와 동일 필드 사본).
 *
 * @param host        대상 호스트
 * @param target      대상 프로세스명/경로
 * @param status      KILLED | NO_MATCH | TIMEOUT | FAILED | COOLDOWN | DISABLED
 * @param executionId 명령 식별자. 에이전트에 내려보낸 그 명령의 id (없으면 null)
 */
public record KillResult(String host, String target, String status, String executionId) {

    /** 실제로 프로세스를 종료한 결과. 이때만 알림을 처리 완료로 넘긴다. */
    public static final String KILLED = "KILLED";

    public boolean killed() {
        return KILLED.equals(status);
    }
}
