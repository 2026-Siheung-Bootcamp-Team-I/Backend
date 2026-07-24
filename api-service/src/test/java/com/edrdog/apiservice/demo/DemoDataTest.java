package com.edrdog.apiservice.demo;

import com.edrdog.apiservice.alert.dto.Alert;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 발표용 과거 데이터 생성(순수). nowTs 를 받아 결정적으로 만들고,
 * 대시보드(호스트 도넛·severity 분포·카테고리)와 lineage 가 모두 채워지는 형태를 보장한다.
 */
class DemoDataTest {

    private static final String TENANT = "1";
    private static final long NOW = 1_770_000_000_000L;   // 고정 기준 시각 (결정성 확인용)

    @Test
    void 같은_입력이면_항상_같은_결과다() {
        assertEquals(DemoData.events(TENANT, NOW), DemoData.events(TENANT, NOW));
        assertEquals(DemoData.alerts(TENANT, NOW), DemoData.alerts(TENANT, NOW));
    }

    @Test
    void 모든_이벤트와_알림이_지정_tenant_로_태깅된다() {
        assertTrue(DemoData.events(TENANT, NOW).stream().allMatch(e -> TENANT.equals(e.tenantId())));
        assertTrue(DemoData.alerts(TENANT, NOW).stream().allMatch(a -> TENANT.equals(a.tenantId())));
    }

    @Test
    void 모든_시각이_과거_구간_안에_들어온다() {
        long oldest = NOW - DemoData.DAYS * 24L * 60 * 60 * 1000;
        assertTrue(DemoData.events(TENANT, NOW).stream().allMatch(e -> e.ts() > oldest && e.ts() <= NOW));
        assertTrue(DemoData.alerts(TENANT, NOW).stream().allMatch(a -> a.ts() > oldest && a.ts() <= NOW));
    }

    @Test
    void 네_종류_룰이_모두_나와_카테고리_집계가_채워진다() {
        Set<String> ruleIds = DemoData.alerts(TENANT, NOW).stream()
                .map(Alert::ruleId)
                .collect(Collectors.toSet());
        assertEquals(Set.of("SUSPICIOUS_PROCESS_CHAIN", "DOWNLOAD_AND_EXECUTE",
                "SCRIPT_FROM_TEMP_PATH", "FILE_IN_AUTORUN_PATH"), ruleIds);
    }

    @Test
    void severity_가_셋_다_나와_분포_차트가_채워진다() {
        Set<String> severities = DemoData.alerts(TENANT, NOW).stream()
                .map(Alert::severity)
                .collect(Collectors.toSet());
        assertEquals(Set.of("CRITICAL", "HIGH", "MEDIUM"), severities);
    }

    @Test
    void action_은_severity_규칙과_일치한다() {
        for (Alert a : DemoData.alerts(TENANT, NOW)) {
            String expected = switch (a.severity()) {
                case "CRITICAL" -> "isolate";
                case "HIGH" -> "kill";
                default -> "notify";
            };
            assertEquals(expected, a.action(), a.ruleId() + " 의 action");
        }
    }

    @Test
    void 조용한_호스트는_이벤트만_있고_알림은_없다() {
        Set<String> alertedHosts = DemoData.alerts(TENANT, NOW).stream()
                .map(Alert::host)
                .collect(Collectors.toSet());
        Set<String> eventHosts = DemoData.events(TENANT, NOW).stream()
                .map(DemoEvent::host)
                .collect(Collectors.toSet());

        assertFalse(DemoData.QUIET_HOSTS.isEmpty(), "정상(초록) 호스트가 있어야 도넛이 한 색으로 안 쏠린다");
        for (String quiet : DemoData.QUIET_HOSTS) {
            assertTrue(eventHosts.contains(quiet), quiet + " 는 events 에 있어야 호스트 목록에 뜬다");
            assertFalse(alertedHosts.contains(quiet), quiet + " 에는 alert 가 없어야 한다");
        }
    }

    @Test
    void 알림마다_같은_호스트_이벤트가_lineage_윈도우_안에_있다() {
        List<DemoEvent> events = DemoData.events(TENANT, NOW);
        long window = 5 * 60 * 1000L;   // AlertService.LINEAGE_WINDOW_MS 와 동일

        for (Alert a : DemoData.alerts(TENANT, NOW)) {
            boolean hasEvidence = events.stream().anyMatch(e ->
                    e.host().equals(a.host())
                            && e.ts() >= a.ts() - window
                            && e.ts() <= a.ts() + window);
            assertTrue(hasEvidence, a.host() + "/" + a.ruleId() + " 의 근거 이벤트가 윈도우 안에 없다");
        }
    }

    @Test
    void 알림에는_판정_근거가_붙어_상세화면이_비지_않는다() {
        assertTrue(DemoData.alerts(TENANT, NOW).stream()
                .allMatch(a -> a.matched() != null && !a.matched().isEmpty()));
    }
}
