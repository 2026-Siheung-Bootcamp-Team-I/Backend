package com.edrdog.apiservice.host;

import com.edrdog.apiservice.host.web.HostResponse;
import com.edrdog.apiservice.intelligence.topology.EgressRelation;
import com.edrdog.apiservice.intelligence.topology.TopologyGraphBuilder;
import com.edrdog.apiservice.intelligence.topology.web.TopologyNode;
import com.edrdog.apiservice.intelligence.topology.web.TopologyResponse;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 같은 호스트를 토폴로지와 엔드포인트 목록 두 화면에서 봤을 때 위험 점수가 같아야 한다.
 * 숫자가 갈리면 어느 쪽을 믿어야 할지 알 수 없으므로, 두 조립기가 같은 severity 분포에서
 * 같은 점수를 내는지 여기서 고정한다(점수 계산은 RiskScore 한 곳만 쓴다).
 */
class HostRiskConsistencyTest {

    private static int listScore(HostRisk risk) {
        List<HostResponse> hosts = HostAggregator.hosts(
                List.of(Map.of("host", risk.host(), "last_seen", "1000")),
                List.of(), List.of(risk), List.of());
        return hosts.get(0).riskScore();
    }

    private static int topologyScore(HostRisk risk) {
        TopologyResponse res = TopologyGraphBuilder.build(1000L, 2000L, 1,
                List.of(new EgressRelation(risk.host(), "api.example.com", "domain", 3, 1500L, List.of())),
                List.of(), List.of(risk));
        return res.nodes().stream()
                .filter(n -> n.id().equals("host:" + risk.host()))
                .map(TopologyNode::riskScore)
                .findFirst()
                .orElseThrow();
    }

    @Test
    void 같은_severity_분포면_두_화면의_점수가_같다() {
        List<HostRisk> cases = List.of(
                new HostRisk("h1", 0, 0, 0, 0),
                new HostRisk("h1", 0, 0, 0, 1),
                new HostRisk("h1", 0, 0, 3, 0),
                new HostRisk("h1", 0, 2, 0, 0),
                new HostRisk("h1", 1, 2, 3, 4),
                new HostRisk("h1", 99, 99, 99, 99));

        for (HostRisk risk : cases) {
            assertEquals(topologyScore(risk), listScore(risk), risk.toString());
        }
    }

    @Test
    void 알림이_없으면_두_화면_모두_0_이다() {
        HostRisk none = new HostRisk("h1", 0, 0, 0, 0);

        assertEquals(0, listScore(none));
        assertEquals(0, topologyScore(none));
    }
}
