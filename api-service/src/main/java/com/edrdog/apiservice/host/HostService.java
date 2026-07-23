package com.edrdog.apiservice.host;

import com.edrdog.apiservice.alert.AlertRepository;
import com.edrdog.apiservice.alert.AlertStatus;
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
 * alerts(MySQL)로 host 별 열린 alert 집계를 각각 뽑아 병합한다. 조회는 항상 tenant 로 격리한다.
 */
@Service
public class HostService {

    private final ClickHouseReader reader;
    private final EventQueryBuilder builder;
    private final AlertRepository alerts;

    public HostService(ClickHouseReader reader, EventQueryBuilder builder, AlertRepository alerts) {
        this.reader = reader;
        this.builder = builder;
        this.alerts = alerts;
    }

    /** tenant 의 관측 호스트 목록(host, last_seen, status, 위협수). last_seen 최신순. */
    public List<HostResponse> hosts(String tenantId) {
        List<Map<String, Object>> rows = reader.query(builder.hostsLastSeen(tenantId));
        List<HostAlertCount> counts = alerts.openAlertCountsByHost(tenantId, AlertStatus.OPEN);
        return HostAggregator.hosts(rows, counts);
    }

    /** tenant 의 도넛용 상태 집계(정상/주의/위험 수 + 총 관측 호스트 수). */
    public HostSummary summary(String tenantId) {
        return HostAggregator.summary(hosts(tenantId));
    }
}
