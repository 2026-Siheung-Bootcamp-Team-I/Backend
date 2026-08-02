package com.edrdog.apiservice.alert;

import com.edrdog.apiservice.alert.web.AlertResponse;
import com.edrdog.apiservice.alert.web.LineageResponse;
import com.edrdog.apiservice.alert.web.SourceEvent;
import com.edrdog.apiservice.alert.web.SummaryResponse;
import com.edrdog.apiservice.auth.exception.AuthException;
import com.edrdog.apiservice.clickhouse.ClickHouseReader;
import com.edrdog.apiservice.query.EventQueryBuilder;
import com.edrdog.apiservice.query.TimeBucket;
import com.edrdog.apiservice.query.TimeseriesFill;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * alert 조회/트리아지 로직. 판정기록(불변)은 archiver 가 ClickHouse(alerts)에 적재하고, 트리아지
 * status(가변)만 이 서비스가 MySQL 오버레이(alert_status)에 둔다.
 * 조회는 ClickHouse 에서 읽어 오버레이 status 를 앱에서 병합한다.
 * 두 저장소라 DB 조인이 안 되므로 필터/병합은 여기서 처리한다(alert 볼륨이 작다는 전제).
 *
 * <p>조회 격리 계약(주의): 저장된 tenant_id 를 로그인 유저의 tenant PK 문자열
 * (String.valueOf(principal.tenantId())) 과 비교한다. 따라서 detector 가 발행하는 alert.tenantId 는
 * 반드시 api-service 의 tenant PK 문자열이어야 한다(아니면 적재는 되지만 조회에서 안 보인다).
 */
@Service
public class AlertService {

    /** lineage 재구성 윈도우: alert.ts 기준 앞뒤 5분. */
    static final long LINEAGE_WINDOW_MS = 5 * 60 * 1000L;

    /** 원본 이벤트를 고르기 위해 훑는 events 상한(EventQueryBuilder 의 상한과 같은 값). */
    static final int SOURCE_EVENT_SCAN_LIMIT = 1000;

    private final AlertStatusRepository statuses;
    private final ClickHouseReader reader;
    private final AlertQueryBuilder alertBuilder;
    private final EventQueryBuilder events;
    private final LineageGraphBuilder lineage;

    public AlertService(AlertStatusRepository statuses, ClickHouseReader reader,
                        AlertQueryBuilder alertBuilder, EventQueryBuilder events, LineageGraphBuilder lineage) {
        this.statuses = statuses;
        this.reader = reader;
        this.alertBuilder = alertBuilder;
        this.events = events;
        this.lineage = lineage;
    }

    /**
     * 한 페이지 분량의 조회 결과. 본문(items)은 배열 그대로 나가고 나머지는 응답 헤더로 실린다.
     * total 은 화면이 요청했을 때만 채워진다(null = 안 셈).
     */
    public record AlertPage(List<AlertResponse> items, boolean hasMore, Long total) {
    }

    /**
     * tenant 격리 하에 필터로 최신순 한 페이지 조회. status 필터는 오버레이(MySQL) 기준으로 id 목록을 구해
     * ClickHouse 쿼리의 IN/NOT IN 으로 옮긴다. 반환 행들의 status 는 오버레이에서 병합한다(없으면 open).
     *
     * <p>offset 은 ORDER BY ts DESC 안에서 앞에서부터 건너뛰므로 호출부가 to 를 고정해 줘야 페이지가
     * 겹치거나 빠지지 않는다. 다음 페이지 유무는 한 행을 더 읽어 판단하고, 총 건수는 withTotal 일 때만
     * 센다: alerts 는 FINAL(중복 제거) 위에서 도는 조회라 count() 를 매번 한 번 더 도는 값이 싸지 않고,
     * 화면은 대개 "다음 페이지가 있는지" 만 알면 되기 때문이다.
     */
    @Transactional(readOnly = true)
    public AlertPage query(String tenantId, String host, String severity, String status,
                           String domain, String destIp, Long from, Long to, Integer limit,
                           Integer offset, boolean withTotal) {
        List<String> includeIds = null;
        List<String> excludeIds = null;
        if (AlertStatus.OPEN.equals(status)) {
            excludeIds = triagedIds(tenantId, null);
        } else if (status != null && !status.isBlank()) {
            includeIds = triagedIds(tenantId, status);
            if (includeIds.isEmpty()) {
                return new AlertPage(List.of(), false, withTotal ? 0L : null);
            }
        }
        int size = AlertQueryBuilder.pageSize(limit);
        List<Map<String, Object>> rows = reader.query(alertBuilder.searchPage(
                tenantId, host, severity, domain, destIp, from, to, limit, offset, includeIds, excludeIds));
        boolean hasMore = rows.size() > size;
        if (hasMore) {
            rows = rows.subList(0, size);   // 탐침으로 더 읽은 한 행은 화면에 주지 않는다
        }
        // open 경로는 반환 행이 이미 전부 트리아지 제외분(=open)이라 오버레이 조회가 불필요하다.
        Map<String, String> overlay = AlertStatus.OPEN.equals(status)
                ? Map.of()
                : statusByIds(rowIds(rows));
        List<AlertResponse> items = rows.stream()
                .map(r -> AlertResponse.fromRow(r, overlay.getOrDefault(str(r, "id"), AlertStatus.OPEN)))
                .toList();
        Long total = withTotal
                ? countOf(tenantId, host, severity, domain, destIp, from, to, includeIds, excludeIds)
                : null;
        return new AlertPage(items, hasMore, total);
    }

    /** 같은 필터·같은 tenant 로 총 건수를 센다(남의 조직 건수가 총계에 섞이면 그 자체로 정보가 샌다). */
    private long countOf(String tenantId, String host, String severity, String domain, String destIp,
                         Long from, Long to, List<String> includeIds, List<String> excludeIds) {
        List<Map<String, Object>> rows = reader.query(alertBuilder.countSearch(
                tenantId, host, severity, domain, destIp, from, to, includeIds, excludeIds));
        return rows.isEmpty() ? 0L : asLong(rows.get(0), "cnt");
    }

    /** 단건 상세. 없거나 다른 tenant 것이면 404(존재 은닉). 판정을 유발한 원본 이벤트를 같이 싣는다. */
    @Transactional(readOnly = true)
    public AlertResponse get(String tenantId, String id) {
        Map<String, Object> row = ownedRow(tenantId, id);
        return AlertResponse.fromRow(row, statusOf(id), sourceEvent(tenantId, row));
    }

    /**
     * 판정을 유발한 원본 이벤트. 같은 tenant+host 의 alert.ts 근처 events 를 긁어와 판별자로 고른다(못 찾으면 null).
     * limit 을 기본값(100)이 아니라 상한으로 두는 건 조회가 ts DESC 라, 실기기처럼 초당 십여 건이 들어오면
     * 정작 alert.ts 근처 행이 잘려 나가기 때문이다. 고르는 규칙은 SourceEventMatcher 에 있다.
     */
    private SourceEvent sourceEvent(String tenantId, Map<String, Object> alert) {
        long ts = asLong(alert, "ts");
        long from = Math.max(0, ts - SourceEventMatcher.WINDOW_MS);
        long to = ts + SourceEventMatcher.WINDOW_MS;
        List<Map<String, Object>> rows = reader.query(
                events.events(tenantId, str(alert, "host"), null, null, from, to, SOURCE_EVENT_SCAN_LIMIT));
        return SourceEventMatcher.match(rows, alert);
    }

    /**
     * 트리아지 갱신. status 검증(confirmed|false_positive) 후 ClickHouse 로 소유/존재 확인,
     * 오버레이(MySQL)에 status 를 upsert 하고 갱신된 응답을 반환한다.
     */
    @Transactional
    public AlertResponse triage(String tenantId, String id, String status) {
        if (!AlertStatus.validTransition(status)) {
            throw AuthException.invalidInput("허용되지 않는 status 입니다: " + status);
        }
        Map<String, Object> row = ownedRow(tenantId, id);
        statuses.save(AlertStatusRecord.of(id, tenantId, status, Instant.now()));
        return AlertResponse.fromRow(row, status);
    }

    /**
     * alert 의 공격 경로 그래프. ClickHouse 판정기록으로 소유(ts/host) 확인 후, 같은 tenant+host 의
     * alert.ts ±5분 윈도우 events 를 시간순으로 긁어와 이름 기반 process/network 체인으로 재구성한다.
     * 없거나 남의 tenant 것이면 404.
     */
    @Transactional(readOnly = true)
    public LineageResponse lineage(String tenantId, String id) {
        Map<String, Object> alert = ownedRow(tenantId, id);
        long ts = asLong(alert, "ts");
        String host = str(alert, "host");
        long from = Math.max(0, ts - LINEAGE_WINDOW_MS);
        long to = ts + LINEAGE_WINDOW_MS;
        List<Map<String, Object>> rows = reader.query(events.lineageEvents(tenantId, host, from, to));
        return lineage.build(rows);
    }

    /** 상수 정렬을 명확히 하려는 severity 리터럴(detector 발행값과 일치). */
    private static final String SEV_CRITICAL = "CRITICAL";
    private static final String SEV_HIGH = "HIGH";
    private static final String SEV_MEDIUM = "MEDIUM";

    static final int TOP_THREATS = 5;

    /**
     * 대시보드 집계. tenant 격리 + 기간(from/to null 이면 무시) 하에 severity 분포와 카테고리별 상위 위협을
     * ClickHouse GROUP BY 로 뽑아 조립한다. status 필터가 없어 오버레이 병합은 불필요하다.
     */
    @Transactional(readOnly = true)
    public SummaryResponse summary(String tenantId, Long from, Long to) {
        long critical = 0;
        long high = 0;
        long medium = 0;
        long total = 0;
        for (Map<String, Object> r : reader.query(alertBuilder.countBySeverity(tenantId, from, to))) {
            long cnt = asLong(r, "cnt");
            total += cnt;
            switch (str(r, "severity")) {
                case SEV_CRITICAL -> critical = cnt;
                case SEV_HIGH -> high = cnt;
                case SEV_MEDIUM -> medium = cnt;
                default -> { /* 미매핑 severity 도 total 에는 포함 */ }
            }
        }

        Map<String, Long> byCategory = new LinkedHashMap<>();
        for (Map<String, Object> r : reader.query(alertBuilder.countByRuleId(tenantId, from, to))) {
            byCategory.merge(ThreatCatalog.category(str(r, "rule_id")), asLong(r, "cnt"), Long::sum);
        }
        List<SummaryResponse.ThreatCount> topThreats = byCategory.entrySet().stream()
                .map(e -> new SummaryResponse.ThreatCount(e.getKey(), e.getValue()))
                .sorted(Comparator.comparingLong(SummaryResponse.ThreatCount::count).reversed()
                        .thenComparing(SummaryResponse.ThreatCount::category))
                .limit(TOP_THREATS)
                .toList();

        return new SummaryResponse(total, new SummaryResponse.Severity(critical, high, medium), topThreats);
    }

    /**
     * 시간대별 탐지 추이(대시보드 스택 차트용). tenant 격리 하에 bucket("hour"|"day") 간격으로
     * severity 별 카운트를 ClickHouse 로 집계한 뒤, 데이터 없는 버킷은 0으로 채워 from~to 전 구간을 반환한다.
     */
    @Transactional(readOnly = true)
    public List<TimeBucket> timeseries(String tenantId, long from, long to, String bucket) {
        long step = TimeseriesFill.stepFor(bucket);
        Map<Long, long[]> byBucket = new HashMap<>(); // [critical, high, medium, total]
        for (Map<String, Object> r : reader.query(alertBuilder.timeseries(tenantId, from, to, step))) {
            long[] acc = byBucket.computeIfAbsent(asLong(r, "bucketStart"), k -> new long[4]);
            long cnt = asLong(r, "cnt");
            acc[3] += cnt;
            switch (str(r, "severity")) {
                case SEV_CRITICAL -> acc[0] += cnt;
                case SEV_HIGH -> acc[1] += cnt;
                case SEV_MEDIUM -> acc[2] += cnt;
                default -> { /* 미매핑 severity 는 total 에만 반영 */ }
            }
        }
        List<TimeBucket> populated = byBucket.entrySet().stream()
                .map(e -> new TimeBucket(e.getKey(), e.getValue()[0], e.getValue()[1], e.getValue()[2], e.getValue()[3]))
                .toList();
        return TimeseriesFill.fill(populated, from, to, step);
    }

    /** ClickHouse 로 tenant 소유의 단건을 읽되 없으면 404 로 숨긴다(없는 것과 구분 불가). */
    private Map<String, Object> ownedRow(String tenantId, String id) {
        List<Map<String, Object>> rows = reader.query(alertBuilder.byId(tenantId, id));
        if (rows.isEmpty()) {
            throw AuthException.notFound("alert 를 찾을 수 없습니다");
        }
        return rows.get(0);
    }

    /** tenant 의 트리아지된 id 목록. status 가 주어지면 그 status 인 것만, null 이면 전부. */
    private List<String> triagedIds(String tenantId, String status) {
        return statuses.findByTenantId(tenantId).stream()
                .filter(r -> status == null || status.equals(r.getStatus()))
                .map(AlertStatusRecord::getId)
                .toList();
    }

    /** id 목록의 오버레이 status 를 한 번에 조회한다(트리아지 안 된 id 는 결과에 없음). */
    private Map<String, String> statusByIds(List<String> ids) {
        if (ids.isEmpty()) {
            return Map.of();
        }
        return statuses.findAllById(ids).stream()
                .collect(Collectors.toMap(AlertStatusRecord::getId, AlertStatusRecord::getStatus));
    }

    /** 단건 id 의 status(오버레이 없으면 open). */
    private String statusOf(String id) {
        return statuses.findById(id).map(AlertStatusRecord::getStatus).orElse(AlertStatus.OPEN);
    }

    private static List<String> rowIds(List<Map<String, Object>> rows) {
        return rows.stream().map(r -> str(r, "id")).toList();
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
