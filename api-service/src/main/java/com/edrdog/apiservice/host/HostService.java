package com.edrdog.apiservice.host;

import com.edrdog.apiservice.alert.AlertQueryBuilder;
import com.edrdog.apiservice.alert.AlertStatusRecord;
import com.edrdog.apiservice.alert.AlertStatusRepository;
import com.edrdog.apiservice.alert.HostAlertCount;
import com.edrdog.apiservice.clickhouse.ClickHouseReader;
import com.edrdog.apiservice.host.web.HostResponse;
import com.edrdog.apiservice.host.web.HostSummary;
import com.edrdog.apiservice.osquery.domain.OsqueryNode;
import com.edrdog.apiservice.osquery.repository.OsqueryNodeRepository;
import com.edrdog.apiservice.query.EventQueryBuilder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

/**
 * 엔드포인트(호스트) 목록·요약 조회. events(ClickHouse)로 관측 호스트+last_seen 을,
 * alerts(ClickHouse)로 host 별 열린 alert 집계를, osquery_nodes(MySQL)로 등록 노드를 각각 뽑아 병합한다.
 * 조회는 항상 tenant 로 격리한다.
 * "열린(open)" 판정은 오버레이(MySQL)에 트리아지된 id 를 빼서 정한다(오버레이 행 없으면 open).
 */
@Service
public class HostService {

    private final ClickHouseReader reader;
    private final EventQueryBuilder builder;
    private final AlertQueryBuilder alertBuilder;
    private final AlertStatusRepository statuses;
    private final OsqueryNodeRepository nodes;

    public HostService(ClickHouseReader reader, EventQueryBuilder builder,
                       AlertQueryBuilder alertBuilder, AlertStatusRepository statuses,
                       OsqueryNodeRepository nodes) {
        this.reader = reader;
        this.builder = builder;
        this.alertBuilder = alertBuilder;
        this.statuses = statuses;
        this.nodes = nodes;
    }

    /**
     * tenant 의 호스트 목록(host, last_seen, status, 위협수, enrolled, agentSeen). last_seen 최신순,
     * 이벤트 없이 등록만 된 기기는 그 뒤에 agentSeen 최신순으로 붙는다.
     */
    public List<HostResponse> hosts(String tenantId) {
        List<Map<String, Object>> rows = reader.query(builder.hostsLastSeen(tenantId));
        List<HostAlertCount> counts = openCounts(tenantId);
        List<EnrolledHost> enrolled = enrolledHosts(tenantId);
        return HostAggregator.hosts(rows, counts, enrolled);
    }

    /** tenant 의 도넛용 상태 집계(정상/주의/위험 수 + 총 호스트 수. 등록만 된 기기도 포함). */
    public HostSummary summary(String tenantId) {
        return HostAggregator.summary(hosts(tenantId));
    }

    /**
     * tenant 의 등록 노드를 순수 값 객체로 변환한다. OsqueryNode.tenantId 는 Long 인데
     * HostService.hosts(String) 은 문자열을 받으므로 변환하되, 숫자가 아닌 값이 와도
     * (예: 잘못된 토큰/테스트 데이터) 예외로 죽이지 않고 빈 목록으로 처리한다.
     */
    private List<EnrolledHost> enrolledHosts(String tenantId) {
        Long id = parseTenantId(tenantId);
        if (id == null) {
            return List.of();
        }
        return nodes.findByTenantId(id).stream()
                .map(HostService::toEnrolledHost)
                .toList();
    }

    private static EnrolledHost toEnrolledHost(OsqueryNode node) {
        return new EnrolledHost(node.getHostIdentifier(), node.getLastSeenAt().toEpochMilli());
    }

    private static Long parseTenantId(String tenantId) {
        try {
            return Long.parseLong(tenantId);
        } catch (NumberFormatException e) {
            return null;
        }
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
