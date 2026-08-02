package com.edrdog.apiservice.intelligence.correlate;

import com.edrdog.apiservice.web.EventResponse;

/**
 * 관측 이벤트 한 건과, 거기에 서버가 덧붙인 추론. inferredProcess 는 못 찾으면 null 이다.
 * 추론값을 EventResponse 안에 채우면 관측한 값과 추측한 값이 같은 자리에 앉아 구분이 사라진다.
 */
public record CorrelatedEvent(EventResponse event, String inferredProcess, String inferenceBasis) {

    public static CorrelatedEvent observed(EventResponse event) {
        return new CorrelatedEvent(event, null, null);
    }
}
