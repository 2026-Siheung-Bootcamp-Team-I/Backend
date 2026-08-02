package com.edrdog.apiservice.intelligence.topology;

import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/**
 * (host → 목적지) 관계 하나의 집계값. destKind 는 "domain" 또는 "ip" 다.
 * protocols 는 관측된 프로토콜 라벨만 담는다(관측 못 했으면 빈 목록).
 */
public record EgressRelation(String host, String dest, String destKind, long events, long lastSeen,
                             List<String> protocols) {

    public static EgressRelation fromRow(Map<String, Object> row) {
        return new EgressRelation(Rows.str(row, "host"), Rows.str(row, "dest"), Rows.str(row, "destKind"),
                Rows.num(row, "events"), Rows.num(row, "lastSeen"),
                protocols(row.get("protocols"), row.get("l7Protocols")));
    }

    /**
     * l4(tcp/udp)와 l7(tls/http) 라벨을 한 목록으로 합친다. JSONExtractString 이 주는 ""는 "관측 못 했다"라 싣지 않는다.
     * 정렬하지 않으면 groupUniqArray 순서가 실행마다 달라 응답이 흔들린다.
     */
    private static List<String> protocols(Object l4, Object l7) {
        TreeSet<String> merged = new TreeSet<>();
        addAll(merged, l4);
        addAll(merged, l7);
        return List.copyOf(merged);
    }

    private static void addAll(TreeSet<String> out, Object value) {
        if (!(value instanceof List<?> list)) {
            return;
        }
        for (Object v : list) {
            String s = v == null ? "" : String.valueOf(v).trim();
            if (!s.isEmpty()) {
                out.add(s);
            }
        }
    }
}
