package com.edrdog.apiservice.demo;

import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 발표용 수집 시나리오 생성(순수). baseTs 를 받아 결정적으로 만들고,
 * detector 룰을 의도한 것만 트리거하도록(배경 로그가 오탐을 만들지 않도록) 보장한다.
 */
class DemoScenarioTest {

    private static final String TENANT = "99";
    private static final long BASE = 1_770_000_000_000L;   // 고정 기준 시각 (결정성 확인용)

    @Test
    void 지원_시나리오는_네_종류다() {
        assertEquals(List.of(DemoScenario.PROCESS_CHAIN, DemoScenario.DOWNLOAD_EXEC,
                DemoScenario.SCRIPT_EXEC, DemoScenario.FILE_AUTORUN), DemoScenario.names());
        assertTrue(DemoScenario.names().stream().allMatch(DemoScenario::isSupported));
        assertFalse(DemoScenario.isSupported("ransomware"));
        assertFalse(DemoScenario.isSupported(null));
    }

    @Test
    void 미지원_시나리오는_예외다() {
        assertThrows(IllegalArgumentException.class,
                () -> DemoScenario.build("ransomware", "PC-01", BASE, TENANT));
    }

    @Test
    void 같은_입력이면_항상_같은_결과다() {
        for (String name : DemoScenario.names()) {
            assertEquals(DemoScenario.build(name, "PC-01", BASE, TENANT),
                    DemoScenario.build(name, "PC-01", BASE, TENANT));
        }
    }

    @Test
    void 모든_이벤트가_지정_host_와_tenant_로_태깅된다() {
        for (String name : DemoScenario.names()) {
            List<CollectedEvent> events = DemoScenario.build(name, "PC-01", BASE, TENANT);
            assertTrue(events.stream().allMatch(e -> "PC-01".equals(e.host())), name);
            assertTrue(events.stream().allMatch(e -> TENANT.equals(e.tenantId())), name);
        }
    }

    @Test
    void 발행_순서가_시간_순서와_같다() {
        // detector 는 host 파티션 안 순서대로 상관하므로 선행 이벤트가 먼저 나가야 룰이 성립한다.
        for (String name : DemoScenario.names()) {
            List<CollectedEvent> events = DemoScenario.build(name, "PC-01", BASE, TENANT);
            for (int i = 1; i < events.size(); i++) {
                assertTrue(events.get(i - 1).ts() <= events.get(i).ts(), name + " #" + i);
            }
        }
    }

    @Test
    void 배경_로그는_공격보다_앞서고_공격은_baseTs_부터_시작한다() {
        for (String name : DemoScenario.names()) {
            List<CollectedEvent> events = DemoScenario.build(name, "PC-01", BASE, TENANT);
            assertTrue(events.stream().anyMatch(e -> e.ts() < BASE), name + " 배경 로그 없음");
            assertTrue(events.stream().anyMatch(e -> e.ts() >= BASE), name + " 공격 이벤트 없음");
        }
    }

    @Test
    void 배경_로그에는_network_이벤트가_없다() {
        // R2 는 선행 network + 이후 process 만으로 CRITICAL 을 내므로, 배경 소음에 network 를 섞으면 뒤 프로세스가 오탐된다.
        for (String name : DemoScenario.names()) {
            List<CollectedEvent> background = DemoScenario.build(name, "PC-01", BASE, TENANT).stream()
                    .filter(e -> e.ts() < BASE)
                    .toList();
            assertTrue(background.stream().noneMatch(e -> CollectedEvent.TYPE_NETWORK.equals(e.type())), name);
        }
    }

    @Test
    void 배경_프로세스는_detector_baseline_억제_대상_이름만_쓴다() {
        // 배경 프로세스는 detector Rules.BASELINE_SAFE 목록에 있는 이름만 써야, 재실행으로 남은 network 이벤트가 R2 오탐(CRITICAL)을 내지 않는다.
        Set<String> baselineSafe = Set.of("onedrive.exe", "teams.exe", "gupdate.exe", "msedgeupdate.exe", "update.exe");
        for (String name : DemoScenario.names()) {
            List<CollectedEvent> background = DemoScenario.build(name, "PC-01", BASE, TENANT).stream()
                    .filter(e -> e.ts() < BASE)
                    .toList();
            assertFalse(background.isEmpty(), name);
            assertTrue(background.stream().allMatch(e -> baselineSafe.contains(e.process().toLowerCase())),
                    name + " 배경 프로세스가 baseline 억제 대상이 아니다");
        }
    }

    @Test
    void network_이벤트는_download_exec_에만_있다() {
        for (String name : DemoScenario.names()) {
            boolean hasNetwork = DemoScenario.build(name, "PC-01", BASE, TENANT).stream()
                    .anyMatch(e -> CollectedEvent.TYPE_NETWORK.equals(e.type()));
            assertEquals(DemoScenario.DOWNLOAD_EXEC.equals(name), hasNetwork, name);
        }
    }

    @Test
    void 판정을_트리거하는_이벤트는_마지막_이벤트다() {
        // 기대 alert 의 ts = 마지막 이벤트 ts. 이 계약으로 alert id 를 미리 계산해 도착을 기다린다.
        List<CollectedEvent> chain = DemoScenario.build(DemoScenario.PROCESS_CHAIN, "PC-01", BASE, TENANT);
        CollectedEvent trigger = chain.get(chain.size() - 1);
        assertEquals("powershell.exe", trigger.process());
        assertEquals("winword.exe", trigger.parent());

        List<CollectedEvent> download = DemoScenario.build(DemoScenario.DOWNLOAD_EXEC, "PC-01", BASE, TENANT);
        assertEquals(CollectedEvent.TYPE_PROCESS, download.get(download.size() - 1).type());
    }

    @Test
    void 시나리오별_기대_룰이_있다() {
        assertEquals("SUSPICIOUS_PROCESS_CHAIN", DemoScenario.expectedRuleId(DemoScenario.PROCESS_CHAIN));
        assertEquals("DOWNLOAD_AND_EXECUTE", DemoScenario.expectedRuleId(DemoScenario.DOWNLOAD_EXEC));
        assertEquals("SCRIPT_FROM_TEMP_PATH", DemoScenario.expectedRuleId(DemoScenario.SCRIPT_EXEC));
        assertEquals("FILE_IN_AUTORUN_PATH", DemoScenario.expectedRuleId(DemoScenario.FILE_AUTORUN));
    }

    @Test
    void 시나리오별_기본_host_가_서로_다르다() {
        // detector 상관 버퍼는 host 별 5분이라 같은 host 로 시나리오를 연달아 돌리면 앞 이벤트가 남아 다른 룰이 먼저 매칭될 수 있다.
        Set<String> hosts = new HashSet<>();
        for (String name : DemoScenario.names()) {
            assertTrue(hosts.add(DemoScenario.defaultHost(name)), name + " host 중복");
        }
    }

    @Test
    void script_와_file_시나리오는_판정_경로를_cmdline_에_담는다() {
        // R3/R4 는 cmdline 의 경로 표식으로 판정한다(process 는 basename).
        List<CollectedEvent> script = DemoScenario.build(DemoScenario.SCRIPT_EXEC, "PC-01", BASE, TENANT);
        CollectedEvent scriptTrigger = script.get(script.size() - 1);
        assertEquals(CollectedEvent.TYPE_SCRIPT, scriptTrigger.type());
        assertTrue(scriptTrigger.cmdline().toLowerCase().contains("\\downloads\\"));

        List<CollectedEvent> file = DemoScenario.build(DemoScenario.FILE_AUTORUN, "PC-01", BASE, TENANT);
        CollectedEvent fileTrigger = file.get(file.size() - 1);
        assertEquals(CollectedEvent.TYPE_FILE, fileTrigger.type());
        assertTrue(fileTrigger.cmdline().toLowerCase().contains("\\startup\\"));
    }
}
