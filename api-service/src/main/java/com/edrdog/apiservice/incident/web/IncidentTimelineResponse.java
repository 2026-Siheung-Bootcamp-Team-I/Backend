package com.edrdog.apiservice.incident.web;

import java.util.List;

/**
 * 사건의 시간순 전개. 사건 체인에 속한 이벤트와 그 위에서 난 알림을 한 줄로 섞어 시간 오름차순으로 준다.
 * 같은 시각이면 이벤트가 먼저다(알림은 그 이벤트 때문에 났다).
 *
 * <p>체인 밖의 이벤트는 담지 않는다. 사건과 이어진다는 관측이 없는 것을 전개에 끼우면 조사하는 사람이
 * 없는 인과를 읽는다.
 */
public record IncidentTimelineResponse(String id, String host, List<Entry> entries) {

    /**
     * 전개 한 줄. {@code kind} 가 event 면 관측된 이벤트, alert 면 그 위에서 난 판정이다.
     * 관측하지 못한 값(pid 등)은 null 로 두고 0 이나 빈 값으로 채우지 않는다.
     *
     * @param kind event | alert
     */
    public record Entry(
            long ts,
            String kind,
            String type,
            String process,
            Integer pid,
            String parent,
            String cmdline,
            String destIp,
            Integer destPort,
            String domain,
            String alertId,
            String ruleId,
            String threatName,
            String severity
    ) {
    }
}
