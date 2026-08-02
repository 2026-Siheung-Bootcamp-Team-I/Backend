package com.edrdog.responderservice.command;

import java.time.Instant;

/**
 * 엔드포인트 에이전트가 하트비트로 가져가는 명령 한 건.
 *
 * <p>종류는 {@code kill_process} 하나뿐이다. 셸 스크립트를 추가하면 에이전트에 임의 코드 실행 채널이 생긴다.
 *
 * @param id        명령 식별자(UUID). 결과 보고와 대기 해제의 키
 * @param host      대상 호스트
 * @param type      명령 종류. 현재는 kill_process
 * @param target    조치 대상. 전체 경로 또는 프로세스명
 * @param createdAt 큐에 들어간 시각. 만료 판단에 쓴다
 */
public record Command(String id, String host, String type, String target, Instant createdAt) {
}
