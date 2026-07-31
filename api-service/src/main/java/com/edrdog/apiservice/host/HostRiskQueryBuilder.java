package com.edrdog.apiservice.host;

import com.edrdog.apiservice.query.ClickHouseQuery;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * host 별 열린 alert 의 severity 분포 SQL(위험 점수 재료). 엔드포인트 목록과 토폴로지가 함께 쓴다.
 * 원래 TopologyQueryBuilder 에 있었으나, 목록이 쓰려면 host 가 intelligence 를 import 해야 해서 이리로 옮겼다.
 *
 * <p>호스트마다 세지 않고 GROUP BY host 한 번으로 전부 가져온다(AlertQueryBuilder.openHostCounts 와 같은 방식).
 * excludeIds 는 오버레이(MySQL)에 트리아지된 alert id 로, HostService 의 "열린(open)" 정의를 그대로 따른다.
 * alerts 조회는 ReplacingMergeTree dedup 때문에 FROM ... FINAL 을 쓴다.
 */
@Component
public class HostRiskQueryBuilder {

    private final String alertsTable;

    public HostRiskQueryBuilder(@Value("${edrdog.clickhouse.alerts-table}") String alertsTable) {
        this.alertsTable = alertsTable;
    }

    /**
     * from/to(epoch millis)는 null 이면 기간을 제한하지 않는다. 토폴로지는 화면이 고른 기간을 주고,
     * 엔드포인트 목록은 기간 개념이 없어 전체를 본다(openHostCounts 와 같은 모집단이라야 위협수와 점수가 어긋나지 않는다).
     */
    public ClickHouseQuery hostSeverityCounts(String tenantId, Long from, Long to, List<String> excludeIds) {
        if (tenantId == null || tenantId.trim().isEmpty()) {
            throw new IllegalArgumentException("tenant 는 필수입니다(격리)");
        }
        Map<String, String> params = new LinkedHashMap<>();
        List<String> conds = new ArrayList<>();
        conds.add("tenant_id = {tenant:String}");
        params.put("tenant", tenantId.trim());
        if (from != null) {
            conds.add("ts >= {from:UInt64}");
            params.put("from", String.valueOf(from));
        }
        if (to != null) {
            conds.add("ts < {to:UInt64}");
            params.put("to", String.valueOf(to));
        }
        addIdSet(excludeIds, conds, params);
        String sql = "SELECT host, "
                + "countIf(severity = 'CRITICAL') AS critical, "
                + "countIf(severity = 'HIGH') AS high, "
                + "countIf(severity = 'MEDIUM') AS medium, "
                + "countIf(severity = 'LOW') AS low"
                + " FROM " + alertsTable + " FINAL WHERE " + String.join(" AND ", conds)
                + " GROUP BY host";
        return new ClickHouseQuery(sql, params);
    }

    /** 제외할 alert id 를 개별 파라미터 바인딩으로 NOT IN 에 넣는다(AlertQueryBuilder.addIdSet 과 같은 방식). */
    private static void addIdSet(List<String> ids, List<String> conds, Map<String, String> params) {
        if (ids == null || ids.isEmpty()) {
            return;
        }
        List<String> placeholders = new ArrayList<>();
        for (int i = 0; i < ids.size(); i++) {
            String name = "exc" + i;
            placeholders.add("{" + name + ":String}");
            params.put(name, ids.get(i));
        }
        conds.add("id NOT IN (" + String.join(", ", placeholders) + ")");
    }
}
