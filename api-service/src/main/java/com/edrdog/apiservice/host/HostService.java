package com.edrdog.apiservice.host;

import com.edrdog.apiservice.alert.AlertQueryBuilder;
import com.edrdog.apiservice.alert.AlertStatusRecord;
import com.edrdog.apiservice.alert.AlertStatusRepository;
import com.edrdog.apiservice.alert.HostAlertCount;
import com.edrdog.apiservice.clickhouse.ClickHouseReader;
import com.edrdog.apiservice.host.web.HostResponse;
import com.edrdog.apiservice.host.web.HostSummary;
import com.edrdog.apiservice.query.EventQueryBuilder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

/**
 * 엔드포인트(호스트) 목록·요약 조회. events(ClickHouse)로 관측 호스트+last_seen 을,
 * alerts(ClickHouse)로 host 별 열린 alert 집계를 각각 뽑아 병합한다. 조회는 항상 tenant 로 격리한다.
 * "열린(open)" 판정은 오버레이(MySQL)에 트리아지된 id 를 빼서 정한다(오버레이 행 없으면 open).
 */
@Service
public class HostService {

    private final ClickHouseReader reader;
    private final EventQueryBuilder builder;
    private final AlertQueryBuilder alertBuilder;
    private final AlertStatusRepository statuses;

    public HostService(ClickHouseReader reader, EventQueryBuilder builder,
                       AlertQueryBuilder alertBuilder, AlertStatusRepository statuses) {
        this.reader = reader;
        this.builder = builder;
        this.alertBuilder = alertBuilder;
        this.statuses = statuses;
    }

    /** tenant 의 관측 호스트 목록(host, last_seen, status, 위협수). last_seen 최신순. */
    public List<HostResponse> hosts(String tenantId) {
        List<Map<String, Object>> rows = reader.query(builder.hostsLastSeen(tenantId));
        List<HostAlertCount> counts = openCounts(tenantId);
        return HostAggregator.hosts(rows, counts);
    }

    /** tenant 의 도넛용 상태 집계(정상/주의/위험 수 + 총 관측 호스트 수). */
    public HostSummary summary(String tenantId) {
        return HostAggregator.summary(hosts(tenantId));
    }

    /** 오버레이의 트리아지된 id 를 제외한 host 별 열린 alert 집계를 ClickHouse 에서 뽑는다. */
    private List<HostAlertCount> openCounts(String tenantId) {
        List<String> triaged = statuses.findByTenantId(tenantId).stream()
                .map(AlertStatusRecord::getId)
                .toList();
        return reader.query(alertBuilder.openHostCounts(tenantId, triaged)).stream()
                .map(HostService::toCount)
                .toList();
    }

    private static HostAlertCount toCount(Map<String, Object> row) {
        return new HostAlertCount(String.valueOf(row.get("host")),
                asLong(row.get("openTotal")), asLong(row.get("openCritical")), asLong(row.get("openHigh")));
    }

    private static long asLong(Object v) {
        return v == null ? 0L : Long.parseLong(String.valueOf(v));
    }
}
