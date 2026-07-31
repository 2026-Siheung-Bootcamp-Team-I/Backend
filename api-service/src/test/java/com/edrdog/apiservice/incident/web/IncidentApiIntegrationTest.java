package com.edrdog.apiservice.incident.web;

import com.edrdog.apiservice.alert.AlertId;
import com.edrdog.apiservice.alert.AlertStatus;
import com.edrdog.apiservice.clickhouse.ClickHouseReader;
import com.edrdog.apiservice.query.ClickHouseQuery;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 전체 컨텍스트로 사건 API 배선(라우팅, Bearer tenant 격리, 계보 묶기, 오버레이 병합, 404)을 검증한다.
 * ClickHouse 는 붙지 않으므로 ClickHouseReader 를 목으로 대체하고, alerts 조회에는 시드 판정기록을
 * events 조회에는 시드 이벤트를 host 로 걸러 돌려준다. 사건 status 오버레이는 H2 로 실제 upsert 된다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.ANY)
@TestPropertySource(properties = "spring.kafka.listener.auto-startup=false")
class IncidentApiIntegrationTest {

    /** 기본 조회 구간(최근 7일) 안에 들어오도록 살짝 과거를 기준으로 잡는다. */
    private static final long BASE_TS = System.currentTimeMillis() - 60_000;

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper om;

    @MockitoBean
    private ClickHouseReader reader;

    private final List<Map<String, Object>> alertRows = new ArrayList<>();
    private final List<Map<String, Object>> eventRows = new ArrayList<>();

    @BeforeEach
    void routeReader() {
        alertRows.clear();
        eventRows.clear();
        when(reader.query(any())).thenAnswer(inv -> {
            ClickHouseQuery q = inv.getArgument(0);
            String tenant = q.params().get("tenant");
            if (q.sql().contains("edrdog.events")) {
                String host = q.params().get("host");
                return eventRows.stream().filter(r -> host.equals(r.get("host"))).toList();
            }
            return alertRows.stream()
                    .filter(r -> tenant.equals(r.get("tenant_id")))
                    .filter(r -> !q.params().containsKey("id") || q.params().get("id").equals(r.get("id")))
                    .toList();
        });
    }

    private String[] signup(String email) throws Exception {
        MvcResult res = mvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"password1\"}"))
                .andExpect(status().isCreated())
                .andReturn();
        var node = om.readTree(res.getResponse().getContentAsString());
        return new String[]{node.get("token").asText(), node.get("tenantId").asText()};
    }

    /** 판정기록 한 건. trigger 는 판정 근거의 마지막 줄이라 원본 이벤트를 여기서 특정한다. */
    private String seedAlert(String tenantId, String host, long ts, String severity, String trigger) {
        String id = AlertId.of(tenantId, host, "SUSPICIOUS_PROCESS_CHAIN", ts);
        Map<String, Object> row = new HashMap<>();
        row.put("id", id);
        row.put("tenant_id", tenantId);
        row.put("host", host);
        row.put("rule_id", "SUSPICIOUS_PROCESS_CHAIN");
        row.put("mitre", "T1059");
        row.put("severity", severity);
        row.put("action", "notify");
        row.put("ts", String.valueOf(ts));
        row.put("matched", List.of(trigger));
        row.put("domain", "");
        row.put("dest_ip", "");
        alertRows.add(row);
        return id;
    }

    private void seedProcess(String host, String process, String parent, long ts, Integer pid, Integer ppid) {
        Map<String, Object> row = new HashMap<>();
        row.put("host", host);
        row.put("type", "process");
        row.put("ts", String.valueOf(ts));
        row.put("process", process);
        row.put("parent", parent);
        row.put("cmdline", "");
        row.put("dest_ip", "");
        row.put("dest_port", 0);
        row.put("domain", "");
        row.put("detail", pid == null ? "" : "{\"pid\":" + pid + ",\"ppid\":" + ppid + "}");
        eventRows.add(row);
    }

    /** winword.exe -> powershell.exe 체인 하나와 그 위의 알림 둘. */
    private void seedChain(String tenantId, String host) {
        seedChainAt(tenantId, host, 0);
    }

    /** 같은 체인을 shiftMs 만큼 옮겨 심는다. 목록 정렬(lastTs 내림차순)이 결정적이어야 페이지 경계를 볼 수 있다. */
    private void seedChainAt(String tenantId, String host, long shiftMs) {
        long ts = BASE_TS + shiftMs;
        seedProcess(host, "winword.exe", "explorer.exe", ts, 10, 1);
        seedProcess(host, "powershell.exe", "winword.exe", ts + 1_000, 100, 10);
        seedAlert(tenantId, host, ts, "MEDIUM", "process winword.exe (parent explorer.exe)");
        seedAlert(tenantId, host, ts + 1_000, "CRITICAL", "process powershell.exe (parent winword.exe)");
    }

    /** hostA/hostB/hostC 에 체인 하나씩. 최근 활동순으로 A, B, C 다. */
    private void seedThreeHosts(String tenantId) {
        seedChainAt(tenantId, "hostA", 0);
        seedChainAt(tenantId, "hostB", -10_000);
        seedChainAt(tenantId, "hostC", -20_000);
    }

    /** 목록 응답의 id 들. 필터·offset 을 걸어도 여기 있던 id 그대로여야 한다. */
    private List<String> listIds(String token, String... params) throws Exception {
        var request = get("/api/incidents").header("Authorization", "Bearer " + token);
        for (int i = 0; i < params.length; i += 2) {
            request = request.param(params[i], params[i + 1]);
        }
        MvcResult res = mvc.perform(request).andExpect(status().isOk()).andReturn();
        List<String> ids = new ArrayList<>();
        om.readTree(res.getResponse().getContentAsString()).forEach(node -> ids.add(node.get("id").asText()));
        return ids;
    }

    private String firstIncidentId(String token) throws Exception {
        MvcResult res = mvc.perform(get("/api/incidents").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andReturn();
        return om.readTree(res.getResponse().getContentAsString()).get(0).get("id").asText();
    }

    @Test
    void 계보로_이어진_알림들은_사건_하나로_묶인다() throws Exception {
        String[] a = signup("a-inc-chain@edrdog.com");
        seedChain(a[1], "hostA");

        mvc.perform(get("/api/incidents").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].host").value("hostA"))
                .andExpect(jsonPath("$[0].alertCount").value(2))
                .andExpect(jsonPath("$[0].severity").value("CRITICAL"))
                .andExpect(jsonPath("$[0].rootProcess").value("winword.exe"))
                .andExpect(jsonPath("$[0].status").value(AlertStatus.OPEN))
                .andExpect(jsonPath("$[0].threatNames[0]").value("의심스러운 프로세스 실행 체인"))
                .andExpect(jsonPath("$[0].alerts").doesNotExist());
    }

    @Test
    void 바쁜_호스트에서_무관한_알림이_한_사건으로_붕괴하지_않는다() throws Exception {
        // 이 기능의 핵심 위험이다. 동명 프로세스를 pid 로 가르지 못하면 여기서 사건이 1개로 뭉친다.
        String[] a = signup("a-inc-busy@edrdog.com");
        seedProcess("hostB", "winword.exe", "explorer.exe", BASE_TS, 10, 1);
        seedProcess("hostB", "powershell.exe", "winword.exe", BASE_TS, 100, 10);
        seedProcess("hostB", "powershell.exe", "explorer.exe", BASE_TS + 2_000, 200, 1);
        seedAlert(a[1], "hostB", BASE_TS, "HIGH", "process powershell.exe (parent winword.exe)");
        seedAlert(a[1], "hostB", BASE_TS + 2_000, "HIGH", "process powershell.exe (parent explorer.exe)");

        mvc.perform(get("/api/incidents").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2))
                .andExpect(jsonPath("$[0].alertCount").value(1))
                .andExpect(jsonPath("$[1].alertCount").value(1));
    }

    @Test
    void 목록은_자기_tenant_것만_보인다() throws Exception {
        String[] a = signup("a-inc-list@edrdog.com");
        String[] b = signup("b-inc-list@edrdog.com");
        seedChain(a[1], "hostA");
        seedChain(b[1], "hostB");

        mvc.perform(get("/api/incidents").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].host").value("hostA"));
    }

    @Test
    void 상세는_구성_알림과_사건_체인_그래프를_싣는다() throws Exception {
        String[] a = signup("a-inc-detail@edrdog.com");
        seedChain(a[1], "hostA");
        String id = firstIncidentId(a[0]);

        mvc.perform(get("/api/incidents/" + id).header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.alerts.length()").value(2))
                .andExpect(jsonPath("$.alerts[0].ruleId").value("SUSPICIOUS_PROCESS_CHAIN"))
                .andExpect(jsonPath("$.lineage.nodes[?(@.id=='proc:powershell.exe:100')].label")
                        .value("powershell.exe"))
                .andExpect(jsonPath("$.lineage.edges[?(@.from=='proc:winword.exe:10')].to")
                        .value("proc:powershell.exe:100"));
    }

    @Test
    void 남의_tenant_사건은_상세_타임라인_트리아지_모두_404() throws Exception {
        String[] a = signup("a-inc-404@edrdog.com");
        String[] b = signup("b-inc-404@edrdog.com");
        seedChain(b[1], "hostB");
        String bId = firstIncidentId(b[0]);

        mvc.perform(get("/api/incidents/" + bId).header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isNotFound());
        mvc.perform(get("/api/incidents/" + bId + "/timeline").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isNotFound());
        mvc.perform(patch("/api/incidents/" + bId + "/status").header("Authorization", "Bearer " + a[0])
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"status\":\"" + AlertStatus.CONFIRMED + "\"}"))
                .andExpect(status().isNotFound());
    }

    @Test
    void 알림이_하나_더_붙어도_트리아지가_유지된다() throws Exception {
        // 사건 id 가 알림 집합으로 흔들리면 여기서 status 가 open 으로 돌아간다.
        String[] a = signup("a-inc-keep@edrdog.com");
        seedChain(a[1], "hostA");
        String id = firstIncidentId(a[0]);

        mvc.perform(patch("/api/incidents/" + id + "/status").header("Authorization", "Bearer " + a[0])
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"status\":\"" + AlertStatus.CONFIRMED + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(AlertStatus.CONFIRMED));

        seedProcess("hostA", "cmd.exe", "powershell.exe", BASE_TS + 2_000, 300, 100);
        seedAlert(a[1], "hostA", BASE_TS + 2_000, "HIGH", "process cmd.exe (parent powershell.exe)");

        mvc.perform(get("/api/incidents").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].id").value(id))
                .andExpect(jsonPath("$[0].alertCount").value(3))
                .andExpect(jsonPath("$[0].status").value(AlertStatus.CONFIRMED));
    }

    @Test
    void 트리아지_잘못된_status_는_400() throws Exception {
        String[] a = signup("a-inc-badstatus@edrdog.com");
        seedChain(a[1], "hostA");
        String id = firstIncidentId(a[0]);

        mvc.perform(patch("/api/incidents/" + id + "/status").header("Authorization", "Bearer " + a[0])
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"status\":\"deleted\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void status_필터는_오버레이_기준이다() throws Exception {
        String[] a = signup("a-inc-filter@edrdog.com");
        seedChain(a[1], "hostA");
        String id = firstIncidentId(a[0]);

        mvc.perform(patch("/api/incidents/" + id + "/status").header("Authorization", "Bearer " + a[0])
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"status\":\"" + AlertStatus.CONFIRMED + "\"}"))
                .andExpect(status().isOk());

        mvc.perform(get("/api/incidents").param("status", AlertStatus.OPEN)
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(0));
        mvc.perform(get("/api/incidents").param("status", AlertStatus.CONFIRMED)
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1));
    }

    @Test
    void 타임라인은_체인_이벤트와_알림을_시간순으로_섞는다() throws Exception {
        String[] a = signup("a-inc-timeline@edrdog.com");
        seedChain(a[1], "hostA");
        // 체인 밖(다른 인스턴스)의 이벤트는 전개에 들어오면 안 된다
        seedProcess("hostA", "chrome.exe", "explorer.exe", BASE_TS + 500, 900, 1);
        String id = firstIncidentId(a[0]);

        mvc.perform(get("/api/incidents/" + id + "/timeline").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.entries.length()").value(4))
                .andExpect(jsonPath("$.entries[0].kind").value("event"))
                .andExpect(jsonPath("$.entries[0].process").value("winword.exe"))
                .andExpect(jsonPath("$.entries[0].pid").value(10))
                .andExpect(jsonPath("$.entries[1].kind").value("alert"))
                .andExpect(jsonPath("$.entries[1].process").value("winword.exe"))
                .andExpect(jsonPath("$.entries[3].kind").value("alert"))
                .andExpect(jsonPath("$.entries[3].severity").value("CRITICAL"))
                .andExpect(jsonPath("$.entries[?(@.process=='chrome.exe')]").isEmpty());
    }

    @Test
    void 원본_이벤트를_못_찾은_알림은_혼자_사건이_된다() throws Exception {
        // 이을 근거가 없으면 잇지 않는다. 알림 하나짜리 사건도 정상적인 결과다.
        String[] a = signup("a-inc-alone@edrdog.com");
        seedChain(a[1], "hostA");
        seedAlert(a[1], "hostA", BASE_TS + 3_000, "HIGH", "process ghost.exe (parent nothing.exe)");

        mvc.perform(get("/api/incidents").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2))
                .andExpect(jsonPath("$[0].alertCount").value(1))
                .andExpect(jsonPath("$[0].rootProcess").value(""));
    }

    @Test
    void host_로_그_호스트_사건만_본다() throws Exception {
        String[] a = signup("a-inc-host@edrdog.com");
        seedThreeHosts(a[1]);

        mvc.perform(get("/api/incidents").param("host", "hostB").param("withTotal", "true")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Total-Count", "1"))
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].host").value("hostB"));

        mvc.perform(get("/api/incidents").param("host", "hostZ").param("withTotal", "true")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Total-Count", "0"))
                .andExpect(jsonPath("$.length()").value(0));
    }

    @Test
    void host_로_걸러도_사건_id_가_같다() throws Exception {
        // 알림 단계에서 걸렀다면 묶기 입력이 달라져 id 가 흔들릴 수 있다. 여기서 그걸 못 하게 고정한다.
        String[] a = signup("a-inc-host-id@edrdog.com");
        seedThreeHosts(a[1]);
        String hostBId = listIds(a[0]).get(1);

        assertThat(listIds(a[0], "host", "hostB")).containsExactly(hostBId);
    }

    @Test
    void offset_은_앞의_사건을_건너뛴다() throws Exception {
        String[] a = signup("a-inc-offset@edrdog.com");
        seedThreeHosts(a[1]);

        mvc.perform(get("/api/incidents").param("offset", "1").param("limit", "1")
                        .param("withTotal", "true")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                // 총계는 잘라내기 전 기준이라 페이지 크기와 무관하다
                .andExpect(header().string("X-Total-Count", "3"))
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].host").value("hostB"));

        mvc.perform(get("/api/incidents").param("offset", "3").param("withTotal", "true")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Total-Count", "3"))
                .andExpect(jsonPath("$.length()").value(0));
    }

    @Test
    void offset_을_줘도_사건_id_가_같다() throws Exception {
        String[] a = signup("a-inc-offset-id@edrdog.com");
        seedThreeHosts(a[1]);
        List<String> all = listIds(a[0]);

        assertThat(listIds(a[0], "offset", "1")).containsExactly(all.get(1), all.get(2));
        assertThat(listIds(a[0], "offset", "2", "limit", "1")).containsExactly(all.get(2));
    }

    @Test
    void 사건_id_는_알림_상세의_incidentId_와_같다() throws Exception {
        // host 필터를 끼워도 알림에서 사건으로 넘어가는 링크가 살아 있어야 한다.
        String[] a = signup("a-inc-link@edrdog.com");
        seedThreeHosts(a[1]);
        String hostBId = listIds(a[0], "host", "hostB").get(0);
        String alertId = AlertId.of(a[1], "hostB", "SUSPICIOUS_PROCESS_CHAIN", BASE_TS - 10_000);

        mvc.perform(get("/api/alerts/" + alertId).header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.incidentId").value(hostBId));
    }

    @Test
    void host_와_offset_을_안_주면_기존과_같다() throws Exception {
        String[] a = signup("a-inc-default@edrdog.com");
        seedThreeHosts(a[1]);

        // 아무 파라미터도 안 주면 헤더까지 포함해 이 기능 전의 응답과 똑같아야 한다.
        mvc.perform(get("/api/incidents").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(header().doesNotExist("X-Total-Count"))
                .andExpect(jsonPath("$.length()").value(3))
                .andExpect(jsonPath("$[0].host").value("hostA"))
                .andExpect(jsonPath("$[1].host").value("hostB"))
                .andExpect(jsonPath("$[2].host").value("hostC"));
    }

    @Test
    void offset_상한을_넘거나_음수면_400() throws Exception {
        String[] a = signup("a-inc-badoffset@edrdog.com");
        seedChain(a[1], "hostA");

        mvc.perform(get("/api/incidents").param("offset", "1001")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isBadRequest());
        mvc.perform(get("/api/incidents").param("offset", "-1")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isBadRequest());
    }

    @Test
    void 총_건수는_자기_tenant_안에서만_센다() throws Exception {
        String[] a = signup("a-inc-total@edrdog.com");
        String[] b = signup("b-inc-total@edrdog.com");
        seedThreeHosts(a[1]);
        seedChainAt(b[1], "hostD", -30_000);
        seedChainAt(b[1], "hostE", -40_000);

        mvc.perform(get("/api/incidents").param("withTotal", "true")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Total-Count", "3"))
                .andExpect(jsonPath("$[?(@.host=='hostD')]").isEmpty())
                .andExpect(jsonPath("$[?(@.host=='hostE')]").isEmpty());
        mvc.perform(get("/api/incidents").param("withTotal", "true")
                        .header("Authorization", "Bearer " + b[0]))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Total-Count", "2"));
    }

    @Test
    void 남의_tenant_호스트를_host_로_찍어도_안_보인다() throws Exception {
        String[] a = signup("a-inc-hostiso@edrdog.com");
        String[] b = signup("b-inc-hostiso@edrdog.com");
        seedChain(a[1], "hostA");
        seedChain(b[1], "hostB");

        mvc.perform(get("/api/incidents").param("host", "hostB").param("withTotal", "true")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Total-Count", "0"))
                .andExpect(jsonPath("$.length()").value(0));
    }

    @Test
    void withTotal_을_안_주면_총계_헤더가_없다() throws Exception {
        // 알림·이벤트 목록과 같은 규약이다. 사건만 늘 헤더를 주면 화면이 목록마다 다르게 읽어야 한다.
        String[] a = signup("a-inc-nototal@edrdog.com");
        seedThreeHosts(a[1]);

        mvc.perform(get("/api/incidents").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(header().doesNotExist("X-Total-Count"))
                .andExpect(jsonPath("$.length()").value(3));
        mvc.perform(get("/api/incidents").param("withTotal", "false")
                        .param("host", "hostB").param("offset", "0")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(header().doesNotExist("X-Total-Count"));
    }

    @Test
    void withTotal_이면_자르기_전_전체_건수가_온다() throws Exception {
        String[] a = signup("a-inc-withtotal@edrdog.com");
        seedThreeHosts(a[1]);

        // limit 1 + offset 2 로 한 건만 받아도 총계는 필터를 통과한 3건이다.
        mvc.perform(get("/api/incidents").param("withTotal", "true")
                        .param("limit", "1").param("offset", "2")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Total-Count", "3"))
                .andExpect(jsonPath("$.length()").value(1));
        // host 로 걸렀으면 총계도 걸러진 뒤 기준이다
        mvc.perform(get("/api/incidents").param("withTotal", "true").param("host", "hostC")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Total-Count", "1"))
                .andExpect(jsonPath("$.length()").value(1));
    }

    @Test
    void 토큰_없으면_401() throws Exception {
        mvc.perform(get("/api/incidents")).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/incidents/anything")).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/incidents/anything/timeline")).andExpect(status().isUnauthorized());
    }
}
