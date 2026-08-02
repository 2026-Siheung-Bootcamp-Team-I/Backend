package com.edrdog.apiservice.incident.web;

import com.edrdog.apiservice.event.EventId;

import java.util.List;

/**
 * 사건의 시간순 전개. 사건 체인에 속한 이벤트와 그 위에서 난 알림을 한 줄로 섞어 시간 오름차순으로 준다.
 * 같은 시각이면 이벤트가 먼저다(알림은 그 이벤트 때문에 났다).
 * 체인 밖 이벤트를 끼우면 조사하는 사람이 없는 인과를 읽으므로 담지 않는다.
 */
public record IncidentTimelineResponse(String id, String host, List<Entry> entries) {

    /** 이벤트 줄의 id 는 host 가 있어야 만들어지는데(EventId) 전개는 한 호스트의 것이라 여기서 한 번에 채운다. */
    public IncidentTimelineResponse {
        entries = entries == null ? null : entries.stream().map(e -> e.withEventId(host)).toList();
    }

    /**
     * 전개 한 줄. {@code kind} 가 event 면 관측된 이벤트, alert 면 그 위에서 난 판정이다.
     * 관측하지 못한 값(pid 등)은 null 로 두고 0 이나 빈 값으로 채우지 않는다.
     *
     * @param eventId 이벤트 줄을 짚는 결정적 id(EventId). /api/events 와 알림 상세의 원본 이벤트에서
     *                같은 값이 나온다. 알림 줄은 {@code alertId} 로 짚으므로 null 이다.
     * @param kind    event | alert
     */
    public record Entry(
            String eventId,
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
        /** 줄을 만들 때는 host 를 모른다. id 는 바깥 record 가 채운다. */
        public Entry(long ts, String kind, String type, String process, Integer pid, String parent,
                     String cmdline, String destIp, Integer destPort, String domain,
                     String alertId, String ruleId, String threatName, String severity) {
            this(null, ts, kind, type, process, pid, parent, cmdline, destIp, destPort, domain,
                    alertId, ruleId, threatName, severity);
        }

        /** 알림 줄은 이벤트가 아니므로 이벤트 id 를 만들지 않는다. 만들면 없는 이벤트를 가리킨다. */
        private Entry withEventId(String host) {
            if (!"event".equals(kind)) {
                return this;
            }
            return new Entry(EventId.of(host, ts, type, process, pid, parent, destIp, destPort),
                    ts, kind, type, process, pid, parent, cmdline, destIp, destPort, domain,
                    alertId, ruleId, threatName, severity);
        }
    }
}
