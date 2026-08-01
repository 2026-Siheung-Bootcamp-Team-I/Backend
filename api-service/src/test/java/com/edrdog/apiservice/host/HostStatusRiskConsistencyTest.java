package com.edrdog.apiservice.host;

import com.edrdog.apiservice.host.web.HostResponse;
import com.edrdog.apiservice.host.web.HostSummary;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 목록 한 행의 status 와 riskScore 가 어긋날 수 없다는 것을 severity 조합 전수로 고정한다.
 * 사례 몇 개를 나열하지 않는 이유: 나중에 가중치나 임계값을 한쪽만 고치면 "열린 알림 54건이라 점수가 100 인데 정상"
 * 같은 모순이 되돌아오는데, 그때 여기서 깨져야 한다.
 */
class HostStatusRiskConsistencyTest {

    /** 전수로 훑는 severity 조합. medium 은 그것만으로 상한(100)을 넘길 만큼 넉넉히 본다. */
    private static final int MAX_CRITICAL = 3;
    private static final int MAX_HIGH = 4;
    private static final int MAX_MEDIUM = 40;
    private static final int MAX_LOW = 12;

    private static final List<HostResponse> ALL = allCombinations();

    /** 위험한 순서. 점수가 오를 때 이 값이 내려가면 안 된다. */
    private static int rank(String status) {
        return switch (status) {
            case HostStatus.CRITICAL -> 2;
            case HostStatus.WARNING -> 1;
            default -> 0;
        };
    }

    /** 모든 severity 조합을 각각 한 호스트로 만들어 실제 목록 조립 경로(HostAggregator)를 통과시킨다. */
    private static List<HostResponse> allCombinations() {
        List<Map<String, Object>> rows = new ArrayList<>();
        List<HostRisk> risks = new ArrayList<>();
        int i = 0;
        for (int c = 0; c <= MAX_CRITICAL; c++) {
            for (int h = 0; h <= MAX_HIGH; h++) {
                for (int m = 0; m <= MAX_MEDIUM; m++) {
                    for (int l = 0; l <= MAX_LOW; l++) {
                        String host = "h" + i++;
                        rows.add(Map.of("host", host, "last_seen", "1000"));
                        risks.add(new HostRisk(host, c, h, m, l));
                    }
                }
            }
        }
        return HostAggregator.hosts(rows, List.of(), risks, List.of());
    }

    @Test
    void 어떤_severity_조합에서도_status_는_riskScore_가_정하는_값과_같다() {
        for (HostResponse h : ALL) {
            assertEquals(HostStatus.classify(h.riskScore()), h.status(),
                    "riskScore=" + h.riskScore() + " 인데 status=" + h.status());
        }
    }

    @Test
    void 정상으로_보이는_호스트는_점수가_주의_임계_미만일_때뿐이다() {
        for (HostResponse h : ALL) {
            if (HostStatus.HEALTHY.equals(h.status())) {
                assertTrue(h.riskScore() < RiskScore.W_HIGH,
                        "점수 " + h.riskScore() + " 인데 정상으로 보인다");
            }
        }
    }

    @Test
    void 위험과_주의는_각_임계_구간에서만_나온다() {
        for (HostResponse h : ALL) {
            int score = h.riskScore();
            String expected = score >= RiskScore.W_CRITICAL ? HostStatus.CRITICAL
                    : score >= RiskScore.W_HIGH ? HostStatus.WARNING
                    : HostStatus.HEALTHY;
            assertEquals(expected, h.status(), "riskScore=" + score);
        }
    }

    @Test
    void 점수가_더_높은_호스트가_더_가벼운_status_로_나오지_않는다() {
        List<HostResponse> byScore = new ArrayList<>(ALL);
        byScore.sort(Comparator.comparingInt(HostResponse::riskScore));
        for (int i = 1; i < byScore.size(); i++) {
            HostResponse lower = byScore.get(i - 1);
            HostResponse higher = byScore.get(i);
            assertTrue(rank(higher.status()) >= rank(lower.status()),
                    "점수 " + higher.riskScore() + " 가 " + lower.riskScore() + " 보다 가볍게 분류됐다");
        }
    }

    @Test
    void 요약의_정상_주의_위험_수는_점수가_정한_분류를_그대로_따른다() {
        Map<String, Long> expected = new HashMap<>();
        for (HostResponse h : ALL) {
            expected.merge(HostStatus.classify(h.riskScore()), 1L, Long::sum);
        }

        HostSummary s = HostAggregator.summary(ALL);
        assertEquals(expected.getOrDefault(HostStatus.HEALTHY, 0L), s.healthy());
        assertEquals(expected.getOrDefault(HostStatus.WARNING, 0L), s.warning());
        assertEquals(expected.getOrDefault(HostStatus.CRITICAL, 0L), s.critical());
        assertEquals(ALL.size(), s.total());
        assertEquals(0L, s.noEvents());
    }
}
