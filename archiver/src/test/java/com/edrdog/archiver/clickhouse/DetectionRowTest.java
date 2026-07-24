package com.edrdog.archiver.clickhouse;

import static org.assertj.core.api.Assertions.assertThat;

import com.edrdog.archiver.dto.Alert;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Alert -> ClickHouse JSONEachRow 한 줄 매핑 순수 로직 검증. */
class DetectionRowTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void alert_를_컬럼순서대로_JSON_object_로_변환한다() {
        Alert a = new Alert("host-1", "SUSPICIOUS_PROCESS_CHAIN", "T1059", "HIGH", "kill",
                1000L, List.of("evidence"), "10.0.0.9", 4444);

        String json = DetectionRow.toJson(a, mapper);

        assertThat(json).isEqualTo(
                "{\"host\":\"host-1\",\"rule_id\":\"SUSPICIOUS_PROCESS_CHAIN\",\"mitre\":\"T1059\","
                        + "\"severity\":\"HIGH\",\"action\":\"kill\",\"ts\":1000,"
                        + "\"dest_ip\":\"10.0.0.9\",\"dest_port\":4444}");
    }

    @Test
    void null_문자열_필드는_빈문자열로_치환한다() {
        Alert a = new Alert("host-2", "RULE", null, "CRITICAL", null,
                2000L, List.of(), null, 0);

        String json = DetectionRow.toJson(a, mapper);

        assertThat(json).isEqualTo(
                "{\"host\":\"host-2\",\"rule_id\":\"RULE\",\"mitre\":\"\","
                        + "\"severity\":\"CRITICAL\",\"action\":\"\",\"ts\":2000,"
                        + "\"dest_ip\":\"\",\"dest_port\":0}");
    }
}
