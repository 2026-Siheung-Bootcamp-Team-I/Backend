package com.edrdog.detectorservice.kafkastreams.topology;

import com.edrdog.detectorservice.dto.Event;

import java.util.ArrayList;
import java.util.List;

/**
 * host 별 이벤트 상태 (state store 값). 두 리스트 모두 이벤트 시각(ts) 오름차순으로 유지한다.
 * Jackson 직렬화를 위해 public 필드 + 기본 생성자 사용.
 */
public class EventBuffer {

    /** prior 최대 보관 개수. 상한이 없으면 폭주 host 하나가 상태 크기를 끝없이 키운다. */
    public static final int MAX = 200;

    /**
     * pending 최대 보관 개수. 시퀀스 트리거만 담아 원래 드물지만, 워터마크가 멈추면 여기가 자란다.
     * prior 보다 작게 잡는다. 넘치면 가장 오래된 것부터 판정하고 비운다.
     */
    public static final int MAX_PENDING = 50;

    /** 선행 근거 후보 (Rules.isCorrelatable 통과분). 프로세서가 윈도우로 정리한다. */
    public List<Event> events = new ArrayList<>();

    /** 워터마크를 기다리는 시퀀스 트리거 (Rules.isSequenceTrigger 통과분). */
    public List<Event> pending = new ArrayList<>();

    /**
     * 이 host 에서 본 가장 늦은 이벤트 시각. 워터마크(maxTs - grace)의 기준이다.
     * 전역 stream-time 을 쓰면 단말마다 다른 전송 시점이 그대로 어긋남이 되어 grace 를 크게 잡아야 한다.
     */
    public long maxTs;

    /**
     * 이 host 의 마지막 갱신 시각(wall clock). 단말이 조용해진 것을 알아내는 데만 쓰고 판정에는 쓰지 않는다.
     * 이게 없으면 이벤트가 끊긴 순간 대기 중이던 마지막 트리거가 영영 판정되지 않는다.
     */
    public long lastUpdatedWallMs;
}
