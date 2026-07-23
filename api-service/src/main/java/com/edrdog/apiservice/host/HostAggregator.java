package com.edrdog.apiservice.host;

import com.edrdog.apiservice.alert.HostAlertCount;
import com.edrdog.apiservice.host.web.HostResponse;
import com.edrdog.apiservice.host.web.HostSummary;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * events(호스트+last_seen)와 alerts(host 별 열린 alert 집계)를 병합하는 순수 로직.
 * 두 저장소(ClickHouse/MySQL)라 SQL 조인이 안 되므로 여기서 host 기준으로 합친다.
 * 호스트 집합은 events 기준이다(관측된 호스트). alert 만 있고 events 없는 host 는 나오지 않는다.
 */
public final class HostAggregator {

    private HostAggregator() {
    }

    /**
     * events 행(host, last_seen)에 host 별 alert 집계를 붙여 목록을 만든다.
     * events 쿼리가 last_seen DESC 로 정렬돼 오므로 그 순서를 그대로 유지한다.
     */
    public static List<HostResponse> hosts(List<Map<String, Object>> eventRows, List<HostAlertCount> alertCounts) {
        Map<String, HostAlertCount> byHost = alertCounts.stream()
                .collect(Collectors.toMap(HostAlertCount::getHost, Function.identity()));

        List<HostResponse> out = new ArrayList<>();
        for (Map<String, Object> row : eventRows) {
            String host = String.valueOf(row.get("host"));
            long lastSeen = Long.parseLong(String.valueOf(row.get("last_seen")));
            HostAlertCount c = byHost.get(host);
            long critical = c == null ? 0 : c.getOpenCritical();
            long high = c == null ? 0 : c.getOpenHigh();
            long threats = c == null ? 0 : c.getOpenTotal();
            out.add(new HostResponse(host, lastSeen, HostStatus.classify(critical, high), threats));
        }
        return out;
    }

    /** 목록의 각 host status 를 세어 도넛용 집계를 만든다. */
    public static HostSummary summary(List<HostResponse> hosts) {
        long healthy = 0;
        long warning = 0;
        long critical = 0;
        for (HostResponse h : hosts) {
            switch (h.status()) {
                case HostStatus.CRITICAL -> critical++;
                case HostStatus.WARNING -> warning++;
                default -> healthy++;
            }
        }
        return new HostSummary(healthy, warning, critical, hosts.size());
    }
}
