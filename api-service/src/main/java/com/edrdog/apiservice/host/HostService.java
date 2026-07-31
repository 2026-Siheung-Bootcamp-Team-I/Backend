package com.edrdog.apiservice.host;

import com.edrdog.apiservice.alert.AlertQueryBuilder;
import com.edrdog.apiservice.alert.AlertStatusRecord;
import com.edrdog.apiservice.alert.AlertStatusRepository;
import com.edrdog.apiservice.alert.HostAlertCount;
import com.edrdog.apiservice.alert.LineageGraphBuilder;
import com.edrdog.apiservice.alert.web.LineageResponse;
import com.edrdog.apiservice.clickhouse.ClickHouseReader;
import com.edrdog.apiservice.host.web.HostResponse;
import com.edrdog.apiservice.host.web.HostSummary;
import com.edrdog.apiservice.agent.domain.AgentNode;
import com.edrdog.apiservice.agent.repository.AgentNodeRepository;
import com.edrdog.apiservice.query.EventQueryBuilder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

/**
 * 엔드포인트(호스트) 목록·요약 조회. events(ClickHouse)로 관측 호스트+last_seen 을,
 * alerts(ClickHouse)로 host 별 열린 alert 집계를, agent_nodes(MySQL)로 등록 노드를 각각 뽑아 병합한다.
 * 조회는 항상 tenant 로 격리한다.
 * "열린(open)" 판정은 오버레이(MySQL)에 트리아지된 id 를 빼서 정한다(오버레이 행 없으면 open).
 */
@Service
public class HostService {

    private final ClickHouseReader reader;
    private final EventQueryBuilder builder;
    private final AlertQueryBuilder alertBuilder;
    private final HostRiskQueryBuilder riskBuilder;
    private final AlertStatusRepository statuses;
    private final AgentNodeRepository nodes;
    private final LineageGraphBuilder lineage;

    public HostService(ClickHouseReader reader, EventQueryBuilder builder,
                       AlertQueryBuilder alertBuilder, HostRiskQueryBuilder riskBuilder,
                       AlertStatusRepository statuses, AgentNodeRepository nodes,
                       LineageGraphBuilder lineage) {
        this.reader = reader;
        this.builder = builder;
        this.alertBuilder = alertBuilder;
        this.riskBuilder = riskBuilder;
        this.statuses = statuses;
        this.nodes = nodes;
        this.lineage = lineage;
    }

    /**
     * tenant 의 호스트 목록(host, last_seen, status, 위협수, riskScore, enrolled, agentSeen). last_seen 최신순,
     * 이벤트 없이 등록만 된 기기는 그 뒤에 agentSeen 최신순으로 붙는다.
     *
     * <p>조회 수는 호스트 수와 무관하게 고정이다(events 1, 열린 alert 집계 1, severity 분포 1 + 오버레이·등록노드 각 1).
     * severity 분포를 따로 한 번 더 읽는 이유는 openHostCounts 가 CRITICAL/HIGH 만 주는데
     * 점수에는 MEDIUM/LOW 도 필요해서다. 트리아지 목록은 두 alert 집계가 같은 "열린" 정의를 쓰도록 한 번만 읽어 공유한다.
     */
    public List<HostResponse> hosts(String tenantId) {
        List<String> triaged = triagedIds(tenantId);
        List<Map<String, Object>> rows = reader.query(builder.hostsLastSeen(tenantId));
        List<HostAlertCount> counts = openCounts(tenantId, triaged);
        List<HostRisk> risks = reader.query(riskBuilder.hostSeverityCounts(tenantId, null, null, triaged))
                .stream().map(HostRisk::fromRow).toList();
        List<EnrolledHost> enrolled = enrolledHosts(tenantId);
        return HostAggregator.hosts(rows, counts, risks, enrolled);
    }

    /** tenant 의 도넛용 상태 집계(정상/주의/위험 수 + 총 호스트 수. 등록만 된 기기도 포함). */
    public HostSummary summary(String tenantId) {
        return HostAggregator.summary(hosts(tenantId));
    }

    /**
     * 엔드포인트 기준 프로세스 계보 그래프. tenant+host 격리 하에 기간[from,to] events 를 시간순으로 긁어와
     * alert lineage 와 같은 재구성기를 태운다(프론트가 같은 렌더러를 쓴다).
     * alert 기준(AlertService.lineage)과 달리 진입점이 호스트라 판정 없이도 그릴 수 있다.
     */
    public LineageResponse processTree(String tenantId, String host, long from, long to) {
        return lineage.build(reader.query(builder.lineageEvents(tenantId, host, from, to)));
    }

    /**
     * tenant 의 등록 노드를 순수 값 객체로 변환한다. AgentNode.tenantId 는 Long 인데
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

    private static EnrolledHost toEnrolledHost(AgentNode node) {
        return new EnrolledHost(node.getHostIdentifier(), node.getLastSeenAt().toEpochMilli(),
                node.getPlatform());
    }

    private static Long parseTenantId(String tenantId) {
        try {
            return Long.parseLong(tenantId);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private List<HostAlertCount> openCounts(String tenantId, List<String> triaged) {
        return reader.query(alertBuilder.openHostCounts(tenantId, triaged)).stream()
                .map(HostService::toCount)
                .toList();
    }

    /** 오버레이(MySQL)에 트리아지된 alert id. 위협수도 위험 점수도 이걸 뺀 "열린" 알림만 센다. */
    private List<String> triagedIds(String tenantId) {
        return statuses.findByTenantId(tenantId).stream()
                .map(AlertStatusRecord::getId)
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
