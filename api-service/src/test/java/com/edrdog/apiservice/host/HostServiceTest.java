package com.edrdog.apiservice.host;

import com.edrdog.apiservice.agent.repository.AgentNodeRepository;
import com.edrdog.apiservice.alert.AlertQueryBuilder;
import com.edrdog.apiservice.alert.AlertStatusRepository;
import com.edrdog.apiservice.alert.LineageGraphBuilder;
import com.edrdog.apiservice.clickhouse.ClickHouseReader;
import com.edrdog.apiservice.host.web.HostResponse;
import com.edrdog.apiservice.query.ClickHouseQuery;
import com.edrdog.apiservice.query.EventQueryBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * 호스트 목록 조회의 배선 검증: 조회 수가 호스트 수에 비례하지 않는지, 모든 ClickHouse 조회가
 * 로그인 tenant 로만 격리되는지, severity 분포가 점수로 붙는지.
 */
class HostServiceTest {

    private static final String TENANT = "7";

    private final ClickHouseReader reader = mock(ClickHouseReader.class);
    private final AlertStatusRepository statuses = mock(AlertStatusRepository.class);
    private final AgentNodeRepository nodes = mock(AgentNodeRepository.class);

    private final List<ClickHouseQuery> issued = new ArrayList<>();
    private List<Map<String, Object>> eventRows = List.of();
    private List<Map<String, Object>> severityRows = List.of();

    private HostService service;

    @BeforeEach
    void setUp() {
        issued.clear();
        eventRows = List.of();
        severityRows = List.of();
        when(statuses.findByTenantId(any())).thenReturn(List.of());
        when(nodes.findByTenantId(anyLong())).thenReturn(List.of());
        // events 조회는 eventRows, severity 분포 조회는 severityRows, 나머지 alerts 집계는 비운다.
        when(reader.query(any())).thenAnswer(inv -> {
            ClickHouseQuery q = inv.getArgument(0);
            issued.add(q);
            if (!q.sql().contains("edrdog.alerts")) {
                return eventRows;
            }
            return q.sql().contains("AS critical") ? severityRows : List.of();
        });
        service = new HostService(reader, new EventQueryBuilder("edrdog.events"),
                new AlertQueryBuilder("edrdog.alerts"), new HostRiskQueryBuilder("edrdog.alerts"),
                statuses, nodes, new LineageGraphBuilder());
    }

    private static Map<String, Object> eventRow(String host) {
        return Map.of("host", host, "last_seen", "1000");
    }

    private static Map<String, Object> severityRow(String host, long critical, long high, long medium, long low) {
        return Map.of("host", host, "critical", String.valueOf(critical), "high", String.valueOf(high),
                "medium", String.valueOf(medium), "low", String.valueOf(low));
    }

    @Test
    void 호스트가_늘어도_조회_횟수는_그대로다() {
        eventRows = List.of(eventRow("h1"));
        service.hosts(TENANT);
        int oneHost = issued.size();

        issued.clear();
        List<Map<String, Object>> many = new ArrayList<>();
        for (int i = 0; i < 50; i++) {
            many.add(eventRow("h" + i));
        }
        eventRows = many;
        assertEquals(50, service.hosts(TENANT).size());

        assertEquals(oneHost, issued.size());
    }

    @Test
    void 모든_조회는_로그인_tenant_로_격리된다() {
        eventRows = List.of(eventRow("h1"));

        service.hosts(TENANT);

        assertTrue(issued.size() >= 3, "조회가 세 번은 나가야 한다: " + issued.size());
        for (ClickHouseQuery q : issued) {
            assertEquals(TENANT, q.params().get("tenant"), q.sql());
            assertTrue(q.sql().contains("tenant_id = {tenant:String}"), q.sql());
        }
    }

    @Test
    void 남의_tenant_행이_섞여_와도_그_호스트는_목록에_없어_점수에_반영되지_않는다() {
        // tenant 격리는 SQL 이 강제하지만, 혹시 다른 조직 host 의 분포가 딸려와도 목록 밖이라 점수가 되지 않는다.
        eventRows = List.of(eventRow("mine"));
        severityRows = List.of(severityRow("mine", 1, 0, 0, 0), severityRow("theirs", 4, 0, 0, 0));

        List<HostResponse> hosts = service.hosts(TENANT);

        assertEquals(1, hosts.size());
        assertEquals("mine", hosts.get(0).host());
        assertEquals(RiskScore.of(1, 0, 0, 0), hosts.get(0).riskScore());
    }

    @Test
    void severity_분포가_없는_호스트는_점수가_0_이다() {
        eventRows = List.of(eventRow("h1"));

        assertEquals(0, service.hosts(TENANT).get(0).riskScore());
    }
}
