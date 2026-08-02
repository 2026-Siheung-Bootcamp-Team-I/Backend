package com.edrdog.apiservice.host;

import com.edrdog.apiservice.alert.HostAlertCount;
import com.edrdog.apiservice.host.web.HostResponse;
import com.edrdog.apiservice.host.web.HostSummary;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * events(호스트+last_seen), alerts(host 별 열린 alert 집계), collector(등록 노드)를 host 기준으로 병합하는 순수 로직.
 * 출처가 셋(ClickHouse/MySQL/collector API)이라 SQL 조인이 안 된다.
 * 호스트 집합은 events ∪ 등록 노드다. 등록 노드를 빼면 이벤트가 0건인 기기가 화면에서 통째로 사라진다.
 */
public final class HostAggregator {

    private HostAggregator() {
    }

    /**
     * events 행(host, last_seen)에 host 별 alert 집계, severity 분포(위험 점수), 등록 노드 정보를 붙여 목록을 만든다.
     * events 쿼리의 last_seen DESC 순서를 그대로 두고, 등록만 된 host 는 agentSeen DESC 로 뒤에 붙인다.
     *
     * <p>status 와 riskScore 를 따로 계산하면 한 행이 "위험도 100 인데 정상" 처럼 반대되는 말을 하므로 한 값에서 같이 낸다.
     * <p>host 이름은 OS 원본 그대로 와 대소문자가 어긋나므로 매칭은 소문자로 하고, 표시명만 events 쪽 원본을 쓴다.
     */
    public static List<HostResponse> hosts(List<Map<String, Object>> eventRows, List<HostAlertCount> alertCounts,
                                            List<HostRisk> risks, List<EnrolledHost> enrolledHosts) {
        Map<String, HostAlertCount> byHost = alertCounts.stream()
                .collect(Collectors.toMap(HostAlertCount::host, Function.identity()));
        Map<String, HostRisk> riskByHost = risks.stream()
                .collect(Collectors.toMap(HostRisk::host, Function.identity(), (a, b) -> a));
        Map<String, EnrolledHost> enrolledByHost = enrolledHosts.stream()
                .collect(Collectors.toMap(e -> e.host().toLowerCase(), Function.identity(), (a, b) -> a));

        List<HostResponse> out = new ArrayList<>();
        Set<String> matched = new HashSet<>();
        for (Map<String, Object> row : eventRows) {
            String host = String.valueOf(row.get("host"));
            long lastSeen = Long.parseLong(String.valueOf(row.get("last_seen")));
            HostAlertCount c = byHost.get(host);
            long threats = c == null ? 0 : c.openTotal();
            HostRisk risk = riskByHost.get(host);
            int score = risk == null ? 0 : risk.score();

            EnrolledHost node = enrolledByHost.get(host.toLowerCase());
            boolean isEnrolled = node != null;
            long agentSeen = node == null ? 0 : node.agentSeen();
            matched.add(host.toLowerCase());

            out.add(new HostResponse(host, lastSeen, HostStatus.classify(score), threats,
                    score, isEnrolled, agentSeen, platformOf(node)));
        }

        enrolledByHost.values().stream()
                .filter(node -> !matched.contains(node.host().toLowerCase()))
                .sorted(Comparator.comparingLong(EnrolledHost::agentSeen).reversed())
                .forEach(node -> out.add(new HostResponse(node.host(), 0L, HostStatus.classify(0), 0L,
                        0, true, node.agentSeen(), platformOf(node))));

        return out;
    }

    /** 미등록이거나 예전에 platform 없이 등록된 노드는 OS 를 모른다(빈 문자열). */
    private static String platformOf(EnrolledHost node) {
        return node == null || node.platform() == null ? "" : node.platform();
    }

    /**
     * 목록의 각 host status 를 세어 도넛용 집계를 만든다.
     * 등록만 되고 이벤트가 없는 기기는 알림이 없어 healthy 로 나오지만 "정상"이 아니라 "아직 관측 없음"이라 noEvents 로 뺀다.
     */
    public static HostSummary summary(List<HostResponse> hosts) {
        long healthy = 0;
        long warning = 0;
        long critical = 0;
        long noEvents = 0;
        for (HostResponse h : hosts) {
            if (h.lastSeen() == 0 && h.enrolled()) {
                noEvents++;
                continue;
            }
            switch (h.status()) {
                case HostStatus.CRITICAL -> critical++;
                case HostStatus.WARNING -> warning++;
                default -> healthy++;
            }
        }
        return new HostSummary(healthy, warning, critical, hosts.size(), noEvents);
    }
}
