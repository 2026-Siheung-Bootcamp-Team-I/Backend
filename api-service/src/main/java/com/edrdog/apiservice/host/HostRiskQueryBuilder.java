package com.edrdog.apiservice.host;

import com.edrdog.apiservice.query.ClickHouseQuery;
import com.edrdog.apiservice.query.TenantScope;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * host 별 열린 alert 의 severity 분포 SQL(위험 점수 재료). 엔드포인트 목록과 토폴로지가 함께 쓴다.
 *
 * <p>excludeIds 는 오버레이(MySQL)에 트리아지된 alert id 로, 이걸 빼야 HostService 의 "열린(open)" 정의와 같아진다.
 * <p>alerts 조회에서 FINAL 을 빼면 ReplacingMergeTree dedup 전 행이 섞여 같은 알림이 여러 번 세어진다.
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
        return TenantScope.of(tenantId)
                .addIfPresent("ts >= {from:UInt64}", "from", from)
                .addIfPresent("ts < {to:UInt64}", "to", to)
                .addNotIn("id", "exc", excludeIds)
                .toQuery("SELECT host, "
                        + "countIf(severity = 'CRITICAL') AS critical, "
                        + "countIf(severity = 'HIGH') AS high, "
                        + "countIf(severity = 'MEDIUM') AS medium, "
                        + "countIf(severity = 'LOW') AS low"
                        + " FROM " + alertsTable + " FINAL", " GROUP BY host");
    }
}
