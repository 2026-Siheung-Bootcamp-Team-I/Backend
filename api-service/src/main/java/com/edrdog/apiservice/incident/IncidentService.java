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

    /**
     * offset 상한. 사건은 한 번에 최대 {@link #ALERT_SCAN_LIMIT} 건의 알림으로 만들어지므로 사건 수도
     * 그보다 많을 수 없고, 그 위의 offset 은 어떤 데이터에서도 빈 페이지다.
     *
     * <p>넘으면 조용히 잘라내지 않고 400 이다. 잘라내면 호출부는 "요청한 범위가 잘못됐다" 와
     * "그 페이지에 사건이 없다" 를 구분할 수 없다.
     */
    public static final int MAX_OFFSET = ALERT_SCAN_LIMIT;

    /**
     * 기본 조회 구간: 최근 7일. 사건은 알림보다 오래 들여다보는 단위라 24시간은 짧다.
     *
     * <p>여기 있는 이유는 사건 id 가 조회 기간에 딸려 나오기 때문이다. 기간이 다르면 묶음의 최초 알림이
     * 달라지고 그러면 id 자체가 달라진다(IncidentId). 그래서 기본 기간을 쓰는 곳이 여럿이어도
     * 값은 하나여야 한다. 복사해 두면 한쪽만 바뀌었을 때 서로 다른 id 를 주고, 그건 조용히 틀린다.
     */
    public static final long DEFAULT_WINDOW_MS = 7 * 24 * 60 * 60 * 1000L;

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

    /**
     * 기간 내 사건 목록(최근 활동순)과 필터를 통과한 전체 건수. status 필터는 오버레이 기준이며,
     * 오버레이 행이 없으면 open 이다.
     *
     * <p><b>host 는 묶은 뒤 사건 단위로 거른다.</b> 알림 조회 단계에서 걸어도 사건은 어차피 호스트별로만
     * 묶이므로(IncidentGrouper) 보통은 결과가 같지만, 알림 스캔이 ALERT_SCAN_LIMIT 에서 잘릴 때 갈린다.
     * 그때 host 를 미리 걸면 그 호스트의 더 오래된 알림이 상한 안으로 들어와 묶음의 최초 알림이 바뀌고,
     * 사건 id 가 통째로 달라진다(IncidentId). 덤으로 eventsByHost 가 그 알림들의 ts 범위로 events 를 읽으므로
     * 계보 재구성 범위까지 달라져 묶음 자체가 흔들린다. 필터에 따라 id 가 바뀌면 트리아지가 떨어져 나가고
     * 알림 상세의 incidentId 와도 어긋나므로, 묶기 입력은 항상 같게 두고 결과만 거른다.
     *
     * <p><b>offset 도 묶은 뒤에 적용한다.</b> 사건 본체 테이블이 없어 DB 에 offset 을 위임할 수 없다.
     * 따라서 offset 이 뒤로 갈수록 싸지지 않는다. 매번 기간 전체를 묶는 비용은 그대로다.
     *
     * <p><b>withTotal 이 false 면 total 은 null 이고 헤더도 안 나간다.</b> 사건은 이미 기간 전체를 묶은
     * 뒤에 자르므로 총계가 사실상 공짜인데도 플래그를 존중하는 이유는 비용이 아니라 사용법이다.
     * 알림·이벤트 목록은 총계를 내려면 같은 WHERE 로 count() 를 한 번 더 돌아야 해서 withTotal=true
     * 일 때만 준다. 사건만 늘 준다면 화면이 "알림·이벤트는 붙이고 사건은 안 붙여도 된다" 를 기억해야
     * 하고, 목록 셋이 같은 패턴을 쓰는 자리에서 그 차이가 곧 버그가 된다. 공짜라고 지우지 마라.
     */
    @Transactional(readOnly = true)
    public IncidentPage query(String tenantId, String status, String host, long from, long to,
                              Integer limit, Integer offset, boolean withTotal) {
        int start = resolveOffset(offset);
        List<Incident> incidents = incidents(tenantId, from, to);
        Map<String, String> overlay = statusByIds(incidents.stream().map(Incident::id).toList());
        List<Incident> matched = incidents.stream()
                .filter(i -> matchesHost(i.host(), host))
                .filter(i -> matchesStatus(overlay.getOrDefault(i.id(), AlertStatus.OPEN), status))
                .toList();
        List<IncidentResponse> page = matched.stream()
                .skip(start)
                .limit(clampLimit(limit))
                .map(i -> summary(i, overlay.getOrDefault(i.id(), AlertStatus.OPEN)))
                .toList();
        // 총계는 tenant 안에서만 센다. 알림 조회에 tenant 가 강제되므로 남의 조직 사건은 애초에 없다.
        return new IncidentPage(page, withTotal ? (long) matched.size() : null);
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

    /**
     * 알림 하나가 속한 사건의 id. 기본 기간 안에서 그 알림을 담은 사건이 없으면 null 이다.
     *
     * <p>기간을 알림 ts 중심의 좁은 창으로 잡지 않는다. 사건 id 의 씨앗이 묶음의 최초 알림이라
     * (IncidentId) 창이 좁으면 더 이른 알림이 묶음에서 빠져 씨앗이 바뀌고, 목록이 주는 id 와 다른
     * id 가 나온다. 그러면 알림에서 사건으로 넘어가는 링크가 404 도 없이 다른 사건을 가리킨다.
     * 그래서 기간을 안 준 목록 조회와 같은 창을 쓴다.
     */
    @Transactional(readOnly = true)
    public String incidentIdOf(String tenantId, String alertId) {
        long to = resolveTo(null);
        long from = resolveFrom(null, to);
        return incidents(tenantId, from, to).stream()
                .filter(i -> i.alerts().stream().anyMatch(a -> alertId.equals(str(a, "id"))))
                .map(Incident::id)
                .findFirst()
                .orElse(null);
    }

    /** 조회 끝점. 안 주면 지금이다. */
    public static long resolveTo(Long to) {
        return to != null ? to : System.currentTimeMillis();
    }

    /** 조회 시작점. 안 주면 끝점에서 기본 구간만큼 거슬러 올라간다. */
    public static long resolveFrom(Long from, long to) {
        return from != null ? from : to - DEFAULT_WINDOW_MS;
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

    /** host 를 안 주면 모든 호스트가 통과한다. 부분 일치를 받지 않는 이유는 호스트 하나를 짚는 동선이라서다. */
    static boolean matchesHost(String actual, String wanted) {
        return wanted == null || wanted.isBlank() || wanted.equals(actual);
    }

    /** 목록 시작 위치. 안 주면 처음부터다. 음수나 상한 초과는 400 이다({@link #MAX_OFFSET}). */
    static int resolveOffset(Integer offset) {
        if (offset == null) {
            return 0;
        }
        if (offset < 0 || offset > MAX_OFFSET) {
            throw AuthException.invalidInput("offset 은 0 이상 " + MAX_OFFSET + " 이하여야 합니다: " + offset);
        }
        return offset;
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
