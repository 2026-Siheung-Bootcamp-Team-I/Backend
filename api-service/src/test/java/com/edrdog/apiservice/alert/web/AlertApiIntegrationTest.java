package com.edrdog.apiservice.alert.web;

import com.edrdog.apiservice.alert.AlertId;
import com.edrdog.apiservice.alert.AlertStatus;
import com.edrdog.apiservice.clickhouse.ClickHouseReader;
import com.edrdog.apiservice.query.ClickHouseQuery;
import com.edrdog.apiservice.responder.KillResult;
import com.edrdog.apiservice.responder.ResponderClient;
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
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 전체 컨텍스트로 alert API 배선(라우팅, Bearer tenant 격리, ClickHouse 읽기 + 오버레이(MySQL) 병합, 예외)을 검증한다.
 * 판정기록(ClickHouse)은 실제로 붙지 않으므로 ClickHouseReader 를 목으로 대체하고, 목이 alerts 테이블 조회에는
 * 시드 판정기록을, events 조회에는 lineage 이벤트를 돌려준다(tenant/id 는 쿼리 파라미터로 걸러 격리를 반영).
 * 오버레이 status 는 H2 로 실제 upsert 된다. 집계(summary/timeseries)는 CH GROUP BY 라 여기서 못 돌리며,
 * SQL 은 AlertQueryBuilderTest, 조립 로직은 AlertServiceTest 로 검증한다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.ANY)
@TestPropertySource(properties = "spring.kafka.listener.auto-startup=false")
class AlertApiIntegrationTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper om;

    @MockitoBean
    private ClickHouseReader reader;

    @MockitoBean
    private ResponderClient responder;

    /** 목 ClickHouse 의 판정기록(alerts 테이블) 시드. tenant/id 필터는 목이 쿼리 파라미터로 반영한다. */
    private final List<Map<String, Object>> alertRows = new ArrayList<>();
    /** 목 ClickHouse 의 events(lineage) 응답. */
    private List<Map<String, Object>> eventRows = List.of();

    @BeforeEach
    void routeReader() {
        alertRows.clear();
        eventRows = List.of();
        when(reader.query(any())).thenAnswer(inv -> {
            ClickHouseQuery q = inv.getArgument(0);
            if (q.sql().contains("edrdog.events")) {
                return eventRows;
            }
            String tenant = q.params().get("tenant");
            return alertRows.stream()
                    .filter(r -> tenant.equals(r.get("tenant_id")))
                    .filter(r -> !q.params().containsKey("id") || q.params().get("id").equals(r.get("id")))
                    .filter(r -> inRange(q.params(), r))
                    .filter(r -> matchesExact(q.params(), r, "domain"))
                    .filter(r -> matchesExact(q.params(), r, "destIp", "dest_ip"))
                    .toList();
        });
    }

    /** ClickHouse 의 domain/dest_ip 등호 필터를 흉내 낸다. 파라미터가 없으면 조건 없는 것과 같다(통과). */
    private static boolean matchesExact(Map<String, String> params, Map<String, Object> row, String key) {
        return matchesExact(params, row, key, key);
    }

    private static boolean matchesExact(Map<String, String> params, Map<String, Object> row, String paramKey, String rowKey) {
        if (!params.containsKey(paramKey)) {
            return true;
        }
        Object v = row.get(rowKey);
        return params.get(paramKey).equals(v == null ? "" : String.valueOf(v));
    }

    /**
     * ClickHouse 의 ts >= from AND ts < to 를 그대로 흉내 낸다. 사건 묶기는 조회 기간에 따라 결과가
     * 갈리므로(기간 밖 알림은 묶음에서 빠진다) 목이 기간을 무시하면 incidentId 를 검증할 수 없다.
     */
    private static boolean inRange(Map<String, String> params, Map<String, Object> row) {
        long ts = Long.parseLong(String.valueOf(row.get("ts")));
        String from = params.get("from");
        String to = params.get("to");
        return (from == null || ts >= Long.parseLong(from)) && (to == null || ts < Long.parseLong(to));
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

    /** 판정기록 한 건을 목 ClickHouse 에 시드한다(ts 는 CH UInt64 처럼 문자열). */
    private String seedAlert(String tenantId, String host, String ruleId, String severity, long ts) {
        String id = AlertId.of(tenantId, host, ruleId, ts);
        Map<String, Object> row = new java.util.HashMap<>(Map.of(
                "id", id, "tenant_id", tenantId, "host", host, "rule_id", ruleId,
                "mitre", "T1059", "severity", severity == null ? "" : severity, "action", "notify",
                "ts", String.valueOf(ts), "matched", List.of("m1")));
        row.put("domain", "evil.example.com");
        row.put("dest_ip", "203.0.113.9");
        alertRows.add(row);
        return id;
    }

    private String seedAlert(String tenantId, String host, long ts) {
        return seedAlert(tenantId, host, "RULE_A", "HIGH", ts);
    }

    /** 판정 근거의 마지막 줄(= 트리거 이벤트 요약)까지 지정해 시드한다. 원본 이벤트는 이 줄로 특정된다. */
    private String seedAlert(String tenantId, String host, long ts, String triggerSummary) {
        String id = seedAlert(tenantId, host, ts);
        alertRows.get(alertRows.size() - 1).put("matched", List.of(triggerSummary));
        return id;
    }

    @Test
    void 목록은_자기_tenant_것만_보인다() throws Exception {
        String[] a = signup("a-list@edrdog.com");
        String[] b = signup("b-list@edrdog.com");
        seedAlert(a[1], "hostA", "DOWNLOAD_AND_EXECUTE", "HIGH", 100L);
        seedAlert(b[1], "hostB", 200L);

        mvc.perform(get("/api/alerts").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].host").value("hostA"))
                .andExpect(jsonPath("$[0].ruleId").value("DOWNLOAD_AND_EXECUTE"))
                .andExpect(jsonPath("$[0].threatName").value("다운로드 후 실행"))
                .andExpect(jsonPath("$[0].status").value("open"));
    }

    @Test
    void 목록은_domain과_destIp로_거를_수_있다() throws Exception {
        // 관계 분석 화면에서 도메인을 짚은 뒤 "이 도메인 때문에 난 알림" 으로 넘어가는 동선을 검증한다.
        String[] a = signup("a-listfilter@edrdog.com");
        seedAlert(a[1], "hostA", 100L); // 기본 시드: domain=evil.example.com, dest_ip=203.0.113.9
        String bId = seedAlert(a[1], "hostB", "RULE_B", "HIGH", 200L);
        Map<String, Object> bRow = alertRows.stream().filter(r -> bId.equals(r.get("id"))).findFirst().orElseThrow();
        bRow.put("domain", "other.example.com");
        bRow.put("dest_ip", "10.0.0.5");

        // 대문자로 줘도 소문자로 정규화된 도메인을 찾는다
        mvc.perform(get("/api/alerts").param("domain", "EVIL.EXAMPLE.COM")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].host").value("hostA"));

        mvc.perform(get("/api/alerts").param("destIp", "10.0.0.5")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].host").value("hostB"));

        // 안 주면 기존과 같이 전부 보인다
        mvc.perform(get("/api/alerts").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2));
    }

    @Test
    void 목록은_목적지를_싣되_원본이벤트는_싣지_않는다() throws Exception {
        // 목록에 원본 이벤트까지 담으면 행마다 events 를 조회해야 해서 느려진다.
        String[] a = signup("a-listdest@edrdog.com");
        seedAlert(a[1], "hostA", 100L);

        mvc.perform(get("/api/alerts").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].domain").value("evil.example.com"))
                .andExpect(jsonPath("$[0].destIp").value("203.0.113.9"))
                .andExpect(jsonPath("$[0].sourceEvent").doesNotExist());
    }

    @Test
    void 상세는_판정을_유발한_원본_이벤트를_싣는다() throws Exception {
        String[] a = signup("a-source@edrdog.com");
        String id = seedAlert(a[1], "hostA", 100L, "process evil.exe (parent explorer.exe)");
        eventRows = List.of(
                Map.of("host", "hostA", "type", "process", "ts", "100",
                        "process", "noise.exe", "parent", "bash",
                        "cmdline", "", "dest_ip", "", "dest_port", 0),
                Map.of("host", "hostA", "type", "process", "ts", "102",
                        "process", "evil.exe", "parent", "explorer.exe",
                        "cmdline", "C:\\Users\\Public\\evil.exe", "dest_ip", "", "dest_port", 0));

        // 시각은 noise.exe 가 더 가깝지만 판정 근거가 짚는 건 evil.exe 다
        mvc.perform(get("/api/alerts/" + id).header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.domain").value("evil.example.com"))
                .andExpect(jsonPath("$.sourceEvent.process").value("evil.exe"))
                .andExpect(jsonPath("$.sourceEvent.parent").value("explorer.exe"))
                .andExpect(jsonPath("$.sourceEvent.cmdline").value("C:\\Users\\Public\\evil.exe"))
                .andExpect(jsonPath("$.sourceEvent.matchedBy").value("summary"));
    }

    @Test
    void 원본_이벤트를_못찾으면_상세의_sourceEvent_는_null() throws Exception {
        String[] a = signup("a-nosource@edrdog.com");
        String id = seedAlert(a[1], "hostA", 100L);
        eventRows = List.of();

        mvc.perform(get("/api/alerts/" + id).header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sourceEvent").doesNotExist());
    }

    @Test
    void 판정_근거와_맞는_이벤트가_없으면_시각으로_아무거나_고르지_않는다() throws Exception {
        // 확신에 차서 틀린 원인을 보여 주는 건 아무것도 안 보여 주는 것보다 나쁘다.
        String[] a = signup("a-wrongsource@edrdog.com");
        String id = seedAlert(a[1], "hostA", 100L, "process evil.exe (parent explorer.exe)");
        eventRows = List.of(Map.of("host", "hostA", "type", "process", "ts", "100",
                "process", "noise.exe", "parent", "bash",
                "cmdline", "", "dest_ip", "", "dest_port", 0));

        mvc.perform(get("/api/alerts/" + id).header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sourceEvent").doesNotExist());
    }

    // --- incidentId (알림이 속한 사건) ---

    /** 기본 조회 구간(최근 7일) 안이라야 사건으로 묶인다. 다른 테스트의 ts(=100)는 구간 밖이라 null 이 된다. */
    private static final long RECENT_TS = System.currentTimeMillis() - 60_000;

    /** 최근 시각의 알림 하나와 그 판정을 유발한 프로세스 이벤트. 이 둘이 있어야 사건이 묶인다. */
    private String seedRecentAlertWithEvent(String tenantId, String host) {
        String id = seedAlert(tenantId, host, RECENT_TS, "process evil.exe (parent explorer.exe)");
        eventRows = List.of(procEvent(host, "evil.exe", "explorer.exe", RECENT_TS));
        return id;
    }

    /**
     * 기본 구간(7일) 안에서 3일 벌어진 채로 이어진 알림 둘. 최근 알림의 id 를 준다.
     *
     * <p>간격이 핵심이다. 알림이 하나뿐이면 창을 좁혀도 그 알림이 그대로 최초 알림이라 id 가 안 변해서,
     * 기간이 어긋난 걸 테스트가 못 잡는다. 3일 전 알림이 창 밖으로 밀리면 씨앗이 바뀌어 id 가 달라진다.
     */
    private String seedChainSpanningDays(String tenantId, String host) {
        long firstTs = System.currentTimeMillis() - 3L * 24 * 60 * 60 * 1000;
        seedAlert(tenantId, host, firstTs, "process winword.exe (parent explorer.exe)");
        String recentId = seedAlert(tenantId, host, RECENT_TS, "process powershell.exe (parent winword.exe)");
        eventRows = List.of(
                procEvent(host, "winword.exe", "explorer.exe", firstTs),
                procEvent(host, "powershell.exe", "winword.exe", RECENT_TS));
        return recentId;
    }

    private static Map<String, Object> procEvent(String host, String process, String parent, long ts) {
        return Map.of("host", host, "type", "process", "ts", String.valueOf(ts),
                "process", process, "parent", parent, "cmdline", "", "dest_ip", "", "dest_port", 0);
    }

    private String incidentIdOfDetail(String token, String alertId) throws Exception {
        MvcResult res = mvc.perform(get("/api/alerts/" + alertId).header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.incidentId").isNotEmpty())
                .andReturn();
        return om.readTree(res.getResponse().getContentAsString()).get("incidentId").asText();
    }

    @Test
    void 상세가_준_incidentId_로_그_사건을_실제로_열_수_있다() throws Exception {
        // 이 기능의 핵심 계약이다. 알림 상세와 사건 목록이 다른 기간을 쓰면 묶음의 최초 알림이 달라져
        // id 가 갈리고, 링크는 404 도 없이 조용히 다른 사건을 가리킨다. 두 경로가 같은 창을 쓰는지 고정한다.
        String[] a = signup("a-incid-link@edrdog.com");
        String alertId = seedChainSpanningDays(a[1], "hostA");

        String incidentId = incidentIdOfDetail(a[0], alertId);

        mvc.perform(get("/api/incidents").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].id").value(incidentId));
        mvc.perform(get("/api/incidents/" + incidentId).header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(incidentId))
                .andExpect(jsonPath("$.alerts.length()").value(2))
                .andExpect(jsonPath("$.alerts[1].id").value(alertId));
    }

    @Test
    void 목록에는_incidentId_가_없다() throws Exception {
        // 행마다 사건을 묶으면 목록 조회가 느려진다. sourceEvent 와 같은 규칙이다.
        String[] a = signup("a-incid-list@edrdog.com");
        seedRecentAlertWithEvent(a[1], "hostA");

        mvc.perform(get("/api/alerts").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].incidentId").doesNotExist());
    }

    @Test
    void 기본_기간_밖의_알림은_incidentId_가_null() throws Exception {
        // 기본 목록에도 그 사건이 안 보이므로 없는 게 맞다. 지어낸 id 를 주면 링크가 404 난다.
        String[] a = signup("a-incid-old@edrdog.com");
        String id = seedAlert(a[1], "hostA", 100L, "process evil.exe (parent explorer.exe)");
        eventRows = List.of(Map.of("host", "hostA", "type", "process", "ts", "100",
                "process", "evil.exe", "parent", "explorer.exe",
                "cmdline", "", "dest_ip", "", "dest_port", 0));

        mvc.perform(get("/api/alerts/" + id).header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sourceEvent.process").value("evil.exe"))
                .andExpect(jsonPath("$.incidentId").doesNotExist());
    }

    @Test
    void 남의_tenant_에는_사건_id_가_새지_않는다() throws Exception {
        String[] a = signup("a-incid-iso@edrdog.com");
        String[] b = signup("b-incid-iso@edrdog.com");
        String bAlertId = seedRecentAlertWithEvent(b[1], "hostB");

        String bIncidentId = incidentIdOfDetail(b[0], bAlertId);

        // 알림 상세부터 404 라 사건 id 를 얻을 길이 없고, 그 id 를 직접 들고 가도 열리지 않는다
        mvc.perform(get("/api/alerts/" + bAlertId).header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isNotFound());
        mvc.perform(get("/api/incidents/" + bIncidentId).header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isNotFound());
    }

    @Test
    void 남의_alert_상세는_404() throws Exception {
        String[] a = signup("a-detail@edrdog.com");
        String[] b = signup("b-detail@edrdog.com");
        String bId = seedAlert(b[1], "hostB", 200L);

        mvc.perform(get("/api/alerts/" + bId).header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isNotFound());
    }

    @Test
    void 자기_alert_트리아지는_200_잘못된_status_400() throws Exception {
        String[] a = signup("a-triage@edrdog.com");
        String id = seedAlert(a[1], "hostA", 100L);

        mvc.perform(patch("/api/alerts/" + id).header("Authorization", "Bearer " + a[0])
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"status\":\"" + AlertStatus.CONFIRMED + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(AlertStatus.CONFIRMED));

        // 오버레이가 실제로 반영됐는지 상세로 재확인
        mvc.perform(get("/api/alerts/" + id).header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(AlertStatus.CONFIRMED));

        mvc.perform(patch("/api/alerts/" + id).header("Authorization", "Bearer " + a[0])
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"status\":\"deleted\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void 남의_alert_트리아지는_404() throws Exception {
        String[] a = signup("a-ptriage@edrdog.com");
        String[] b = signup("b-ptriage@edrdog.com");
        String bId = seedAlert(b[1], "hostB", 200L);

        mvc.perform(patch("/api/alerts/" + bId).header("Authorization", "Bearer " + a[0])
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"status\":\"" + AlertStatus.CONFIRMED + "\"}"))
                .andExpect(status().isNotFound());
    }

    @Test
    void 토큰_없으면_401() throws Exception {
        mvc.perform(get("/api/alerts")).andExpect(status().isUnauthorized());
    }

    // --- respond (kill 프록시) ---

    @Test
    void 자기_alert_respond_는_알림host로_responder에_위임한다() throws Exception {
        String[] a = signup("a-respond@edrdog.com");
        String id = seedAlert(a[1], "hostA", 100L);
        when(responder.kill(eq("hostA"), eq("evil.exe")))
                .thenReturn(new KillResult("hostA", "evil.exe", "KILLED", "exec-1"));

        mvc.perform(post("/api/alerts/" + id + "/respond").header("Authorization", "Bearer " + a[0])
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"target\":\"evil.exe\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.host").value("hostA"))
                .andExpect(jsonPath("$.status").value("KILLED"))
                .andExpect(jsonPath("$.executionId").value("exec-1"));

        // host 는 알림에서 오고 클라이언트 입력이 아님을 확인
        verify(responder).kill("hostA", "evil.exe");
    }

    @Test
    void 조치가_성공하면_알림이_confirmed_로_넘어간다() throws Exception {
        // 조치했는데 알림이 open 그대로면 목록에서 처리 여부를 알 수 없다.
        String[] a = signup("a-respond-confirm@edrdog.com");
        String id = seedAlert(a[1], "hostC", 300L);
        when(responder.kill(eq("hostC"), eq("evil.exe")))
                .thenReturn(new KillResult("hostC", "evil.exe", "KILLED", "exec-2"));

        mvc.perform(post("/api/alerts/" + id + "/respond").header("Authorization", "Bearer " + a[0])
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"target\":\"evil.exe\"}"))
                .andExpect(status().isOk());

        mvc.perform(get("/api/alerts/" + id).header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("confirmed"));
    }

    @Test
    void 조치가_실패하면_알림_상태를_바꾸지_않는다() throws Exception {
        // 종료되지 않았는데 처리된 것처럼 보이면 안 된다.
        String[] a = signup("a-respond-fail@edrdog.com");
        String id = seedAlert(a[1], "hostD", 400L);
        when(responder.kill(eq("hostD"), eq("evil.exe")))
                .thenReturn(new KillResult("hostD", "evil.exe", "FAILED", null));

        mvc.perform(post("/api/alerts/" + id + "/respond").header("Authorization", "Bearer " + a[0])
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"target\":\"evil.exe\"}"))
                .andExpect(status().isOk());

        mvc.perform(get("/api/alerts/" + id).header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("open"));
    }

    @Test
    void 남의_alert_respond_는_404이고_responder를_호출하지_않는다() throws Exception {
        String[] a = signup("a-presp@edrdog.com");
        String[] b = signup("b-presp@edrdog.com");
        String bId = seedAlert(b[1], "hostB", 200L);

        mvc.perform(post("/api/alerts/" + bId + "/respond").header("Authorization", "Bearer " + a[0])
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"target\":\"evil.exe\"}"))
                .andExpect(status().isNotFound());

        verify(responder, never()).kill(any(), any());
    }

    @Test
    void respond_target_없으면_400() throws Exception {
        String[] a = signup("a-respnotarget@edrdog.com");
        String id = seedAlert(a[1], "hostA", 100L);

        mvc.perform(post("/api/alerts/" + id + "/respond").header("Authorization", "Bearer " + a[0])
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"target\":\"  \"}"))
                .andExpect(status().isBadRequest());

        verify(responder, never()).kill(any(), any());
    }

    @Test
    void respond_토큰_없으면_401() throws Exception {
        mvc.perform(post("/api/alerts/anything/respond")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"target\":\"evil.exe\"}"))
                .andExpect(status().isUnauthorized());

        verify(responder, never()).kill(any(), any());
    }

    // --- lineage ---

    private static Map<String, Object> procRow(String process, String parent) {
        return Map.of("type", "process", "ts", 100L, "process", process, "parent", parent,
                "dest_ip", "", "dest_port", 0);
    }

    private static Map<String, Object> netRow(String process, String ip, int port) {
        return Map.of("type", "network", "ts", 100L, "process", process, "parent", "",
                "dest_ip", ip, "dest_port", port);
    }

    @Test
    void 자기_alert_lineage_는_이름체인_그래프를_돌려준다() throws Exception {
        String[] a = signup("a-lineage@edrdog.com");
        String id = seedAlert(a[1], "hostA", 100L);
        eventRows = List.of(procRow("child.exe", "root.exe"), netRow("child.exe", "10.0.0.9", 4444));

        mvc.perform(get("/api/alerts/" + id + "/lineage").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.nodes.length()").value(3))
                .andExpect(jsonPath("$.edges.length()").value(2))
                .andExpect(jsonPath("$.edges[?(@.rel=='spawned')].from").value("proc:root.exe"))
                .andExpect(jsonPath("$.edges[?(@.rel=='connected')].to").value("net:10.0.0.9:4444"));
    }

    @Test
    void 이벤트가_없으면_lineage_는_빈_그래프_200() throws Exception {
        String[] a = signup("a-emptylineage@edrdog.com");
        String id = seedAlert(a[1], "hostA", 100L);
        eventRows = List.of();

        mvc.perform(get("/api/alerts/" + id + "/lineage").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.nodes.length()").value(0))
                .andExpect(jsonPath("$.edges.length()").value(0));
    }

    @Test
    void 남의_alert_lineage_는_404() throws Exception {
        String[] a = signup("a-plineage@edrdog.com");
        String[] b = signup("b-plineage@edrdog.com");
        String bId = seedAlert(b[1], "hostB", 200L);

        mvc.perform(get("/api/alerts/" + bId + "/lineage").header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isNotFound());
    }

    @Test
    void lineage_도_토큰_없으면_401() throws Exception {
        mvc.perform(get("/api/alerts/anything/lineage")).andExpect(status().isUnauthorized());
    }

    @Test
    void summary_토큰_없으면_401() throws Exception {
        mvc.perform(get("/api/alerts/summary")).andExpect(status().isUnauthorized());
    }
}
