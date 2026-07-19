package com.edrdog.detector.kafkastreams.topology;

import com.edrdog.detector.dto.Event;

import java.util.ArrayList;
import java.util.List;

/**
 * host 별 최근 이벤트 버퍼 (state store 값). 윈도우 밖 이벤트는 프로세서가 pruning 한다.
 * Jackson 직렬화를 위해 public 필드 + 기본 생성자 사용.
 */
public class EventBuffer {

    /** 최대 보관 개수 — 폭주 host 로부터 상태 크기를 방어. */
    public static final int MAX = 200;

    public List<Event> events = new ArrayList<>();
}
