package com.edrdog.apiservice.alert;

import com.edrdog.apiservice.alert.dto.Alert;
import com.edrdog.apiservice.alert.web.AlertResponse;
import com.edrdog.apiservice.alert.web.LineageResponse;
import com.edrdog.apiservice.auth.exception.AuthException;
import com.edrdog.apiservice.clickhouse.ClickHouseReader;
import com.edrdog.apiservice.query.EventQueryBuilder;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
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
