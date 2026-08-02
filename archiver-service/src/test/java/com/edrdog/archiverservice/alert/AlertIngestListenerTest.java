package com.edrdog.archiverservice.alert;

import com.edrdog.archiverservice.alert.dto.Alert;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * api-service AlertService.ingest 의 방어 조건(tenantId/host/ruleId 없으면 skip)이
 * archiver 리스너로 옮겨와서도 그대로 지켜지는지 확인한다.
 */
class AlertIngestListenerTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final AlertClickHouseWriter writer = mock(AlertClickHouseWriter.class);
    private final AlertIngestListener listener = new AlertIngestListener(writer, mapper);

    @Test
    void tenantId_없으면_버린다() throws Exception {
        listener.onAlert(json(alert(null, "host-1", "RULE_A")));
        verify(writer, never()).insert(any(), any());
    }

    @Test
    void tenantId_가_빈문자열이면_버린다() throws Exception {
        listener.onAlert(json(alert("", "host-1", "RULE_A")));
        verify(writer, never()).insert(any(), any());
    }

    @Test
    void host_없으면_버린다() throws Exception {
        listener.onAlert(json(alert("t1", null, "RULE_A")));
        verify(writer, never()).insert(any(), any());
    }

    @Test
    void ruleId_없으면_버린다() throws Exception {
        listener.onAlert(json(alert("t1", "host-1", null)));
        verify(writer, never()).insert(any(), any());
    }

    @Test
    void 파싱_실패한_메시지는_버린다() {
        listener.onAlert("{이건 JSON 이 아니다");
        verify(writer, never()).insert(any(), any());
    }

    @Test
    void 필수값이_다있으면_결정적_id로_적재한다() throws Exception {
        Alert alert = alert("t1", "host-1", "RULE_A");
        listener.onAlert(json(alert));
        String expectedId = AlertId.of("t1", "host-1", "RULE_A", 1000L);
        verify(writer).insert(eq(expectedId), eq(alert));
    }

    private Alert alert(String tenantId, String host, String ruleId) {
        return new Alert(host, ruleId, "T1059", "HIGH", "block", 1000L, List.of(), tenantId, "", "");
    }

    private String json(Alert alert) throws Exception {
        return mapper.writeValueAsString(alert);
    }
}
