package com.edrdog.apiservice.alert;

import com.edrdog.apiservice.alert.dto.Alert;
import com.edrdog.apiservice.alert.web.AlertResponse;
import com.edrdog.apiservice.alert.web.LineageResponse;
import com.edrdog.apiservice.alert.web.SummaryResponse;
import com.edrdog.apiservice.auth.exception.AuthException;
import com.edrdog.apiservice.clickhouse.ClickHouseReader;
import com.edrdog.apiservice.query.EventQueryBuilder;
import com.edrdog.apiservice.query.TimeBucket;
import com.edrdog.apiservice.query.TimeseriesFill;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * alert 적재/조회/트리아지 로직. 리스너·컨트롤러는 얇게 두고 여기서 tenant 격리와 멱등 적재를 담당한다.
 */
@Service
public class AlertService {

    static final int DEFAULT_LIMIT = 100;
    static final int MAX_LIMIT = 1000;

    /** lineage 재구성 윈도우: alert.ts 기준 앞뒤 5분. */
    static final long LINEAGE_WINDOW_MS = 5 * 60 * 1000L;

    private final AlertRepository alerts;
    private final ClickHouseReader reader;
    private final EventQueryBuilder events;
    private final LineageGraphBuilder lineage;

    public AlertService(AlertRepository alerts, ClickHouseReader reader,
                        EventQueryBuilder events, LineageGraphBuilder lineage) {
        this.alerts = alerts;
        this.reader = reader;
        this.events = events;
        this.lineage = lineage;
    }

    /**
     * alert 를 적재한다. id 는 결정적(AlertId)이라 재소비돼도 한 행만 남는다.
     * 이미 있으면 덮어쓰지 않는다(트리아지된 status 보존). tenantId 없는 alert 는 skip.
     *
     * 계약(주의): 조회 격리는 저장된 tenantId 를 로그인 유저의 tenant PK 문자열
     * (String.valueOf(principal.tenantId())) 과 equals 비교한다. 따라서 detector 가
     * 발행하는 alert.tenantId 는 반드시 api-service 의 tenant PK 문자열이어야 한다.
     * (조직명/UUID 등 다른 표현이면 저장은 되지만 조회에서 매칭되지 않아 alert 가 안 보인다.)
     */
    @Transactional
    public void ingest(Alert alert) {
        if (alert == null || alert.tenantId() == null || alert.tenantId().isBlank()
                || alert.host() == null || alert.ruleId() == null) {
            return;
        }
        String id = AlertId.of(alert.tenantId(), alert.host(), alert.ruleId(), alert.ts());
        if (alerts.existsById(id)) {
            return;
        }
        AlertRecord record = AlertRecord.open(id, alert.tenantId(), alert.host(), alert.ruleId(),
                alert.mitre(), alert.severity(), alert.action(), alert.ts(), alert.matched(), Instant.now());
        alerts.save(record);
    }

    /** tenant 격리 하에 필터로 최신순 조회. limit 은 1..MAX 로 클램프. */
    @Transactional(readOnly = true)
    public List<AlertResponse> query(String tenantId, String host, String severity, String status,
                                     Long from, Long to, Integer limit) {
        Pageable page = PageRequest.of(0, clampLimit(limit));
        return alerts.search(tenantId, host, severity, status, from, to, page).stream()
                .map(AlertResponse::from)
                .toList();
    }

    /** 단건 상세. 없거나 다른 tenant 것이면 404(존재 은닉). */
    @Transactional(readOnly = true)
    public AlertResponse get(String tenantId, String id) {
        return AlertResponse.from(owned(tenantId, id));
    }

    /** 트리아지 갱신. status 검증(confirmed|false_positive) 후 소유 확인, 갱신 결과 반환. */
    @Transactional
    public AlertResponse triage(String tenantId, String id, String status) {
        if (!AlertStatus.validTransition(status)) {
            throw AuthException.invalidInput("허용되지 않는 status 입니다: " + status);
        }
        AlertRecord record = owned(tenantId, id);
        record.triage(status, Instant.now());
        return AlertResponse.from(record);
    }

    /**
     * alert 의 공격 경로 그래프. 소유 확인 후, 같은 tenant+host 의 alert.ts ±5분 윈도우 events 를
     * 시간순으로 긁어와 이름 기반 process/network 체인으로 재구성한다. 없거나 남의 tenant 것이면 404.
     */
    @Transactional(readOnly = true)
    public LineageResponse lineage(String tenantId, String id) {
        AlertRecord alert = owned(tenantId, id);
        long from = Math.max(0, alert.getTs() - LINEAGE_WINDOW_MS);
        long to = alert.getTs() + LINEAGE_WINDOW_MS;
        List<Map<String, Object>> rows = reader.query(
                events.lineageEvents(tenantId, alert.getHost(), from, to));
        return lineage.build(rows);
    }

    /** 상수 정렬을 명확히 하려는 severity 리터럴(detector 발행값과 일치). */
    private static final String SEV_CRITICAL = "CRITICAL";
    private static final String SEV_HIGH = "HIGH";
    private static final String SEV_MEDIUM = "MEDIUM";

    /** 카테고리 topThreats 상위 개수. */
    static final int TOP_THREATS = 5;

    /**
     * 대시보드 집계. tenant 격리 + 기간(from/to null 이면 무시) 하에 severity 분포와
     * 카테고리별 상위 위협을 조립한다. total 은 모든 severity 버킷 합이라 매핑 안 되는
     * severity(null/미래값)도 포함돼 topThreats(모든 row 집계) 합과 정합이 맞는다(추가 쿼리 없음).
     */
    @Transactional(readOnly = true)
    public SummaryResponse summary(String tenantId, Long from, Long to) {
        long critical = 0;
        long high = 0;
        long medium = 0;
        long total = 0;
        for (SeverityCount c : alerts.countBySeverity(tenantId, from, to)) {
            total += c.getCnt();
            if (SEV_CRITICAL.equals(c.getSeverity())) {
                critical = c.getCnt();
            } else if (SEV_HIGH.equals(c.getSeverity())) {
                high = c.getCnt();
            } else if (SEV_MEDIUM.equals(c.getSeverity())) {
                medium = c.getCnt();
            }
        }

        Map<String, Long> byCategory = new LinkedHashMap<>();
        for (RuleIdCount c : alerts.countByRuleId(tenantId, from, to)) {
            byCategory.merge(ThreatCatalog.category(c.getRuleId()), c.getCnt(), Long::sum);
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
     * severity 별 카운트를 집계한 뒤, 데이터 없는 버킷은 0으로 채워 from~to 전 구간을 반환한다.
     */
    @Transactional(readOnly = true)
    public List<TimeBucket> timeseries(String tenantId, long from, long to, String bucket) {
        long step = TimeseriesFill.stepFor(bucket);
        Map<Long, long[]> byBucket = new HashMap<>(); // [critical, high, medium, total]
        for (TimeBucketSeverityCount row : alerts.timeseries(tenantId, from, to, step)) {
            long[] acc = byBucket.computeIfAbsent(row.getBucketStart(), k -> new long[4]);
            acc[3] += row.getCnt();
            if (SEV_CRITICAL.equals(row.getSeverity())) {
                acc[0] += row.getCnt();
            } else if (SEV_HIGH.equals(row.getSeverity())) {
                acc[1] += row.getCnt();
            } else if (SEV_MEDIUM.equals(row.getSeverity())) {
                acc[2] += row.getCnt();
            }
        }
        List<TimeBucket> populated = byBucket.entrySet().stream()
                .map(e -> new TimeBucket(e.getKey(), e.getValue()[0], e.getValue()[1], e.getValue()[2], e.getValue()[3]))
                .toList();
        return TimeseriesFill.fill(populated, from, to, step);
    }

    /** id 로 찾되 tenant 소유가 아니면 404 로 숨긴다(없는 것과 구분 불가). */
    private AlertRecord owned(String tenantId, String id) {
        return alerts.findById(id)
                .filter(a -> a.getTenantId().equals(tenantId))
                .orElseThrow(() -> AuthException.notFound("alert 를 찾을 수 없습니다"));
    }

    private static int clampLimit(Integer limit) {
        if (limit == null || limit <= 0) {
            return DEFAULT_LIMIT;
        }
        return Math.min(limit, MAX_LIMIT);
    }
}
