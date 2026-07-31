package com.edrdog.apiservice.incident;

import com.edrdog.apiservice.alert.AlertQueryBuilder;
import com.edrdog.apiservice.alert.AlertStatus;
import com.edrdog.apiservice.alert.AlertStatusRecord;
import com.edrdog.apiservice.alert.AlertStatusRepository;
import com.edrdog.apiservice.alert.LineageGraphBuilder;
import com.edrdog.apiservice.alert.SourceEventMatcher;
import com.edrdog.apiservice.alert.ThreatCatalog;
import com.edrdog.apiservice.alert.web.AlertResponse;
import com.edrdog.apiservice.alert.web.LineageResponse;
import com.edrdog.apiservice.alert.web.SourceEvent;
import com.edrdog.apiservice.auth.exception.AuthException;
import com.edrdog.apiservice.clickhouse.ClickHouseReader;
import com.edrdog.apiservice.incident.web.IncidentResponse;
import com.edrdog.apiservice.incident.web.IncidentTimelineResponse;
import com.edrdog.apiservice.query.EventQueryBuilder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 사건(incident) 조회·트리아지. <b>사건 본체 테이블은 없다.</b> 조회할 때마다 기간 내 알림을 읽어
 * 프로세스 계보로 묶어 만들고(IncidentGrouper), 가변인 트리아지 status 만 MySQL 오버레이에서 병합한다
 * (alert 이 ClickHouse 판정기록 + alert_status 오버레이인 것과 같은 구조).
 *
 * <p>본체를 저장하지 않는 이유: 알림이 늦게 도착하거나 재판정되면 미리 만들어 둔 사건과 어긋나고,
 * 그 정합성을 맞추는 코드가 계속 늘어난다. 대신 id 가 결정적이어야 트리아지가 붙어 있는다(IncidentId).
 *
 * <p>그래서 단건 조회도 "id 로 한 행 읽기" 가 아니라 기간을 다시 묶어 그 안에서 찾는 것이다.
 * 컨트롤러가 기본 기간을 주고, 그 기간 밖의 사건은 404 다.
 */
@Service
public class IncidentService {

    /** 계보를 재구성할 때 알림 앞뒤로 더 보는 폭. AlertService.LINEAGE_WINDOW_MS 와 같은 값이다. */
    static final long LINEAGE_WINDOW_MS = 5 * 60 * 1000L;

    /** 한 번에 묶을 알림 수 상한(AlertQueryBuilder 상한과 같다). 넘치면 오래된 쪽이 잘린다. */
    static final int ALERT_SCAN_LIMIT = 1000;

    /** 계보 재구성에 훑는 events 상한(EventQueryBuilder 상한과 같다). */
    static final int EVENT_SCAN_LIMIT = 1000;

    static final int DEFAULT_LIMIT = 100;
    static final int MAX_LIMIT = 1000;

    private final ClickHouseReader reader;
    private final AlertQueryBuilder alertBuilder;
    private final EventQueryBuilder events;
    private final IncidentStatusRepository statuses;
    private final AlertStatusRepository alertStatuses;
    private final LineageGraphBuilder lineage;

    public IncidentService(ClickHouseReader reader, AlertQueryBuilder alertBuilder, EventQueryBuilder events,
                           IncidentStatusRepository statuses, AlertStatusRepository alertStatuses,
                           LineageGraphBuilder lineage) {
        this.reader = reader;
        this.alertBuilder = alertBuilder;
        this.events = events;
        this.statuses = statuses;
        this.alertStatuses = alertStatuses;
        this.lineage = lineage;
    }

    /** 기간 내 사건 목록(최근 활동순). status 필터는 오버레이 기준이며, 오버레이 행이 없으면 open 이다. */
    @Transactional(readOnly = true)
    public List<IncidentResponse> query(String tenantId, String status, long from, long to, Integer limit) {
        List<Incident> incidents = incidents(tenantId, from, to);
        Map<String, String> overlay = statusByIds(incidents.stream().map(Incident::id).toList());
        return incidents.stream()
                .filter(i -> matchesStatus(overlay.getOrDefault(i.id(), AlertStatus.OPEN), status))
                .limit(clampLimit(limit))
                .map(i -> summary(i, overlay.getOrDefault(i.id(), AlertStatus.OPEN)))
                .toList();
    }

    /** 단건 상세(구성 알림 + 사건 체인만 남긴 계보 그래프). 없거나 남의 tenant 것이면 404(존재 은닉). */
    @Transactional(readOnly = true)
    public IncidentResponse get(String tenantId, String id, long from, long to) {
        Incident incident = owned(tenantId, id, from, to);
        String status = statusOf(id);
        List<Map<String, Object>> chain = chainEvents(tenantId, incident);
        // 구성 알림은 사건과 별개로 개별 트리아지될 수 있으므로 alert 오버레이를 그대로 병합한다.
        Map<String, String> perAlert = alertStatusByIds(
                incident.alerts().stream().map(r -> str(r, "id")).toList());
        List<AlertResponse> alerts = incident.alerts().stream()
                .map(r -> AlertResponse.fromRow(r, perAlert.getOrDefault(str(r, "id"), AlertStatus.OPEN)))
                .toList();
        return detail(incident, status, alerts, lineage.build(chain));
    }

    /** 사건의 시간순 전개. 체인에 속한 이벤트와 그 위에서 난 알림을 섞어 시간 오름차순으로 준다. */
    @Transactional(readOnly = true)
    public IncidentTimelineResponse timeline(String tenantId, String id, long from, long to) {
        Incident incident = owned(tenantId, id, from, to);
        List<Map<String, Object>> hostEvents = hostEvents(tenantId, incident);
        Set<String> chain = Set.copyOf(incident.chainNodes());

        List<IncidentTimelineResponse.Entry> entries = new ArrayList<>();
        hostEvents.stream()
                .filter(row -> chain.contains(nodeOf(row)))
                .map(IncidentService::eventEntry)
                .forEach(entries::add);
        incident.alerts().stream()
                .map(alert -> alertEntry(alert, SourceEventMatcher.match(hostEvents, alert)))
                .forEach(entries::add);

        // 같은 시각이면 이벤트가 먼저다. 알림은 그 이벤트 때문에 났다.
        entries.sort(Comparator.comparingLong(IncidentTimelineResponse.Entry::ts)
                .thenComparing(e -> "alert".equals(e.kind()) ? 1 : 0));
        return new IncidentTimelineResponse(incident.id(), incident.host(), List.copyOf(entries));
    }

    /** 트리아지 갱신. status 검증 후 사건 존재/소유를 확인하고 오버레이에 upsert 한다. */
    @Transactional
    public IncidentResponse triage(String tenantId, String id, String status, long from, long to) {
        if (!AlertStatus.validTransition(status)) {
            throw AuthException.invalidInput("허용되지 않는 status 입니다: " + status);
        }
        Incident incident = owned(tenantId, id, from, to);
        statuses.save(IncidentStatusRecord.of(id, tenantId, status, Instant.now()));
        return summary(incident, status);
    }

    /**
     * 기간 내 알림을 읽어 사건으로 묶는다. 알림 조회에 tenant 가 강제되므로(AlertQueryBuilder)
     * 남의 조직 알림은 애초에 들어오지 않는다.
     */
    private List<Incident> incidents(String tenantId, long from, long to) {
        List<Map<String, Object>> alerts = reader.query(
                alertBuilder.search(tenantId, null, null, from, to, ALERT_SCAN_LIMIT, null, null));
        return IncidentGrouper.group(tenantId, alerts, eventsByHost(tenantId, alerts));
    }

    /**
     * 알림이 난 호스트마다 그 알림들의 시각 ±5분 events 를 읽는다.
     *
     * <p>lineageEvents 가 아니라 events 를 쓰는 이유는 원본 이벤트를 짚는 SourceEventMatcher 가
     * cmdline(file 룰)까지 보기 때문이다. 알림이 없는 호스트는 아예 읽지 않는다.
     */
    private Map<String, List<Map<String, Object>>> eventsByHost(String tenantId, List<Map<String, Object>> alerts) {
        Map<String, long[]> spans = new LinkedHashMap<>();   // host -> [min ts, max ts]
        for (Map<String, Object> alert : alerts) {
            long ts = asLong(alert, "ts");
            spans.compute(str(alert, "host"), (h, span) -> span == null
                    ? new long[]{ts, ts}
                    : new long[]{Math.min(span[0], ts), Math.max(span[1], ts)});
        }
        Map<String, List<Map<String, Object>>> out = new LinkedHashMap<>();
        spans.forEach((host, span) -> out.put(host, readEvents(tenantId, host, span[0], span[1])));
        return out;
    }

    private List<Map<String, Object>> readEvents(String tenantId, String host, long firstTs, long lastTs) {
        return reader.query(events.events(tenantId, host, null, null,
                Math.max(0, firstTs - LINEAGE_WINDOW_MS), lastTs + LINEAGE_WINDOW_MS, EVENT_SCAN_LIMIT));
    }

    private List<Map<String, Object>> hostEvents(String tenantId, Incident incident) {
        return readEvents(tenantId, incident.host(), incident.firstTs(), incident.lastTs());
    }

    /** 사건 체인에 속한 이벤트만 남긴다. 체인 밖 이벤트를 그래프에 넣으면 사건이 다시 부풀어 오른다. */
    private List<Map<String, Object>> chainEvents(String tenantId, Incident incident) {
        Set<String> chain = Set.copyOf(incident.chainNodes());
        return hostEvents(tenantId, incident).stream()
                .filter(row -> chain.contains(nodeOf(row)))
                .toList();
    }

    /** 계산된 사건 중 id 가 맞는 것. 없으면 404 로 숨긴다(남의 tenant 사건은 애초에 계산되지 않는다). */
    private Incident owned(String tenantId, String id, long from, long to) {
        return incidents(tenantId, from, to).stream()
                .filter(i -> i.id().equals(id))
                .findFirst()
                .orElseThrow(() -> AuthException.notFound("사건을 찾을 수 없습니다"));
    }

    private static String nodeOf(Map<String, Object> row) {
        String process = str(row, "process");
        if (process.isEmpty()) {
            return "";
        }
        return LineageGraphBuilder.processNodeId(process, LineageGraphBuilder.detailOf(str(row, "detail")).pid());
    }

    private static IncidentTimelineResponse.Entry eventEntry(Map<String, Object> row) {
        var detail = LineageGraphBuilder.detailOf(str(row, "detail"));
        Integer port = row.get("dest_port") == null ? null : (int) asLong(row, "dest_port");
        return new IncidentTimelineResponse.Entry(asLong(row, "ts"), "event", str(row, "type"),
                str(row, "process"), detail.pid(), str(row, "parent"), str(row, "cmdline"),
                str(row, "dest_ip"), port, str(row, "domain"), null, null, null, null);
    }

    /** 알림 한 줄. source 는 그 판정을 유발한 이벤트로, 못 찾았으면 프로세스를 비워 둔다. */
    private static IncidentTimelineResponse.Entry alertEntry(Map<String, Object> alert, SourceEvent source) {
        String ruleId = str(alert, "rule_id");
        return new IncidentTimelineResponse.Entry(asLong(alert, "ts"), "alert", null,
                source == null ? null : source.process(), null, null, null, null, null, str(alert, "domain"),
                str(alert, "id"), ruleId, ThreatCatalog.threatName(ruleId), str(alert, "severity"));
    }

    private static IncidentResponse summary(Incident incident, String status) {
        return detail(incident, status, null, null);
    }

    private static IncidentResponse detail(Incident incident, String status,
                                           List<AlertResponse> alerts, LineageResponse graph) {
        List<String> ruleIds = incident.alerts().stream().map(r -> str(r, "rule_id")).distinct().toList();
        List<String> mitre = incident.alerts().stream().map(r -> str(r, "mitre"))
                .filter(m -> !m.isEmpty()).distinct().toList();
        return new IncidentResponse(incident.id(), incident.host(), status, incident.severity(),
                incident.firstTs(), incident.lastTs(), incident.alerts().size(), incident.rootProcess(),
                ruleIds, ruleIds.stream().map(ThreatCatalog::threatName).toList(), mitre, alerts, graph);
    }

    private static boolean matchesStatus(String actual, String wanted) {
        return wanted == null || wanted.isBlank() || wanted.equals(actual);
    }

    private Map<String, String> statusByIds(List<String> ids) {
        if (ids.isEmpty()) {
            return Map.of();
        }
        return statuses.findAllById(ids).stream()
                .collect(Collectors.toMap(IncidentStatusRecord::getId, IncidentStatusRecord::getStatus));
    }

    /** 구성 알림들의 개별 트리아지 status(alert 오버레이). 없는 id 는 결과에 없다. */
    private Map<String, String> alertStatusByIds(List<String> ids) {
        if (ids.isEmpty()) {
            return Map.of();
        }
        return alertStatuses.findAllById(ids).stream()
                .collect(Collectors.toMap(AlertStatusRecord::getId, AlertStatusRecord::getStatus));
    }

    private String statusOf(String id) {
        return statuses.findById(id).map(IncidentStatusRecord::getStatus).orElse(AlertStatus.OPEN);
    }

    private static int clampLimit(Integer limit) {
        if (limit == null || limit <= 0) {
            return DEFAULT_LIMIT;
        }
        return Math.min(limit, MAX_LIMIT);
    }

    private static String str(Map<String, Object> row, String key) {
        Object v = row.get(key);
        return v == null ? "" : String.valueOf(v);
    }

    private static long asLong(Map<String, Object> row, String key) {
        Object v = row.get(key);
        if (v == null) {
            return 0L;
        }
        if (v instanceof Number n) {
            return n.longValue();
        }
        return Long.parseLong(String.valueOf(v));
    }
}
