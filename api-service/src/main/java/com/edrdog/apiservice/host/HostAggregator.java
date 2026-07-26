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
 * events(호스트+last_seen), alerts(host 별 열린 alert 집계), osquery_nodes(등록 노드)를 병합하는 순수 로직.
 * 세 저장소(ClickHouse/MySQL)라 SQL 조인이 안 되므로 여기서 host 기준으로 합친다.
 * 호스트 집합은 events ∪ 등록 노드다. osquery 가 enroll 에 성공해도 이벤트가 0건이면 화면에서
 * 기기 상태를 전혀 볼 수 없었던 문제 때문에, 이벤트 없이 등록만 된 기기도 목록에 넣는다.
 * alert 만 있고 events/등록 둘 다 없는 host 는 여전히 나오지 않는다.
 */
public final class HostAggregator {

    private HostAggregator() {
    }

    /**
     * events 행(host, last_seen)에 host 별 alert 집계와 등록 노드 정보를 붙여 목록을 만든다.
     * events 쿼리가 last_seen DESC 로 정렬돼 오므로 그 순서를 그대로 유지하고,
     * events 는 없고 등록만 된 host 는 agentSeen DESC 로 정렬해 뒤에 붙인다.
     * host 이름은 osquery 가 OS 원본 그대로 보내 대소문자가 어긋나는 사례가 있어(Fleet 조회에서 겪음)
     * 매칭은 소문자로 하되, 화면 표시명은 events 쪽 원본을 우선한다.
     */
    public static List<HostResponse> hosts(List<Map<String, Object>> eventRows, List<HostAlertCount> alertCounts,
                                            List<EnrolledHost> enrolledHosts) {
        Map<String, HostAlertCount> byHost = alertCounts.stream()
                .collect(Collectors.toMap(HostAlertCount::host, Function.identity()));
        Map<String, EnrolledHost> enrolledByHost = enrolledHosts.stream()
                .collect(Collectors.toMap(e -> e.host().toLowerCase(), Function.identity(), (a, b) -> a));

        List<HostResponse> out = new ArrayList<>();
        Set<String> matched = new HashSet<>();
        for (Map<String, Object> row : eventRows) {
            String host = String.valueOf(row.get("host"));
            long lastSeen = Long.parseLong(String.valueOf(row.get("last_seen")));
            HostAlertCount c = byHost.get(host);
            long critical = c == null ? 0 : c.openCritical();
            long high = c == null ? 0 : c.openHigh();
            long threats = c == null ? 0 : c.openTotal();

            EnrolledHost node = enrolledByHost.get(host.toLowerCase());
            boolean isEnrolled = node != null;
            long agentSeen = node == null ? 0 : node.agentSeen();
            matched.add(host.toLowerCase());

            out.add(new HostResponse(host, lastSeen, HostStatus.classify(critical, high), threats,
                    isEnrolled, agentSeen));
        }

        // 이벤트 없이 등록만 된 기기: 위협 없는 정상 상태로 목록 뒤에 붙인다.
        enrolledByHost.values().stream()
                .filter(node -> !matched.contains(node.host().toLowerCase()))
                .sorted(Comparator.comparingLong(EnrolledHost::agentSeen).reversed())
                .forEach(node -> out.add(new HostResponse(node.host(), 0L, HostStatus.HEALTHY, 0L,
                        true, node.agentSeen())));

        return out;
    }

    /**
     * 목록의 각 host status 를 세어 도넛용 집계를 만든다.
     * 등록만 되고 이벤트가 한 번도 없는 기기(lastSeen=0 && enrolled)는 알림이 없어 status 가 healthy 로
     * 나오지만 그건 "정상"이 아니라 "아직 관측된 적 없음"이라 healthy 에서 빼서 noEvents 로 센다.
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
