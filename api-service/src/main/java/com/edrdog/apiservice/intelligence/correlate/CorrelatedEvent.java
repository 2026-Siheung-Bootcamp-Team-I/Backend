package com.edrdog.apiservice.intelligence.correlate;

import com.edrdog.apiservice.web.EventResponse;

/**
 * 관측 이벤트 한 건과, 거기에 서버가 덧붙인 추론.
 *
 * <p>추론값을 EventResponse 안에 채워 넣지 않고 밖에 두는 이유: 에이전트는 확신할 수 없는
 * 프로세스를 아예 비워 보낸다(l7.go 의 dnsEvent 주석). 그 빈칸을 서버가 조용히 메우면
 * 관측한 값과 이어 붙여 추측한 값이 같은 자리에 앉아 구분이 사라진다.
 *
 * <p>inferredProcess 는 못 찾으면 null 이다. 에이전트와 같은 선택으로, 틀린 값을 채우느니 비운다.
 */
public record CorrelatedEvent(EventResponse event, String inferredProcess, String inferenceBasis) {

    public static CorrelatedEvent observed(EventResponse event) {
        return new CorrelatedEvent(event, null, null);
    }
}
