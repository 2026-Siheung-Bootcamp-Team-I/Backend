package com.edrdog.apiservice.intelligence.topology;

import java.util.Map;

/** (host → 목적지) 관계 하나에서 난 알림 수. 엣지를 실선/점선으로 가르는 값이다. */
public record RelationAlertCount(String host, String dest, long alerts) {

    public static RelationAlertCount fromRow(Map<String, Object> row) {
        return new RelationAlertCount(Rows.str(row, "host"), Rows.str(row, "dest"), Rows.num(row, "alerts"));
    }
}
