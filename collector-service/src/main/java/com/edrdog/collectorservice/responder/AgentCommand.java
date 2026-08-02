package com.edrdog.collectorservice.responder;

/**
 * 하트비트에 실어 내려줄 대응 명령. responder 가 큐에 넣어 둔 것을 그대로 전달한다.
 *
 * @param id     명령 식별자. 에이전트가 이미 실행한 id 를 기억해 중복 실행을 건너뛴다
 * @param type   명령 종류(kill_process)
 * @param target 대상. 전체 경로면 경로로, 아니면 프로세스명으로 찾는다
 */
public record AgentCommand(String id, String type, String target) {
}
