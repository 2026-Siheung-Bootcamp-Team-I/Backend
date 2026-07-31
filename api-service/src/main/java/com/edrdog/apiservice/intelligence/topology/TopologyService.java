package com.edrdog.apiservice.intelligence.topology;

import com.edrdog.apiservice.alert.AlertStatusRecord;
import com.edrdog.apiservice.alert.AlertStatusRepository;
import com.edrdog.apiservice.clickhouse.ClickHouseReader;
import com.edrdog.apiservice.intelligence.topology.web.TopologyResponse;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

/**
 * egress 토폴로지 조회. events(관계)와 alerts(관계별 알림 수, 호스트 위험 점수)를 각각 집계해 그래프로 합친다.
 * 조회는 항상 tenant 로 격리한다.
 *
 * <p>관계는 이벤트 많은 순 Top-N 으로 자르되, 자르기 전 전체 수를 함께 세서 응답에 담는다.
 */
@Service
public class TopologyService {

    private final ClickHouseReader reader;
    private final TopologyQueryBuilder builder;
    private final AlertStatusRepository statuses;

    public TopologyService(ClickHouseReader reader, TopologyQueryBuilder builder,
                           AlertStatusRepository statuses) {
        this.reader = reader;
        this.builder = builder;
        this.statuses = statuses;
    }

    public TopologyResponse topology(String tenantId, long from, long to, String search, Integer limit) {
        List<EgressRelation> relations = reader.query(builder.egressRelations(tenantId, from, to, search, limit))
                .stream().map(EgressRelation::fromRow).toList();
        long total = totalRelations(tenantId, from, to, search);
        List<RelationAlertCount> alertCounts = reader.query(builder.relationAlertCounts(tenantId, from, to))
                .stream().map(RelationAlertCount::fromRow).toList();
        List<HostRisk> risks = reader.query(builder.hostSeverityCounts(tenantId, from, to, triagedIds(tenantId)))
                .stream().map(HostRisk::fromRow).toList();
        return TopologyGraphBuilder.build(from, to, total, relations, alertCounts, risks);
    }

    private long totalRelations(String tenantId, long from, long to, String search) {
        List<Map<String, Object>> rows = reader.query(builder.relationTotal(tenantId, from, to, search));
        return rows.isEmpty() ? 0L : asLong(rows.get(0).get("total"));
    }

    /** 오버레이(MySQL)에 트리아지된 alert id. 위험 점수는 이걸 뺀 "열린" 알림만 센다(HostService 와 같은 정의). */
    private List<String> triagedIds(String tenantId) {
        return statuses.findByTenantId(tenantId).stream().map(AlertStatusRecord::getId).toList();
    }

    private static long asLong(Object v) {
        return v == null ? 0L : Long.parseLong(String.valueOf(v));
    }
}
