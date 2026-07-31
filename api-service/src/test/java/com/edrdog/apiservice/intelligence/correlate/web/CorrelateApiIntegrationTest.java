package com.edrdog.apiservice.intelligence.correlate.web;

import com.edrdog.apiservice.clickhouse.ClickHouseReader;
import com.edrdog.apiservice.intelligence.correlate.DnsResolver;
import com.edrdog.apiservice.intelligence.correlate.ForwardLookup;
import com.edrdog.apiservice.intelligence.correlate.ReverseLookup;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 전체 컨텍스트로 correlate/dns-lookup 배선(라우팅, Bearer tenant 격리, 입력 검증, 조회 실패 격리)을 검증한다.
 *
 * <p>이 층이 따로 필요한 이유: 쿼리 빌더·서비스 테스트는 "받은 tenant 로 조회한다"까지만 보장한다.
 * 컨트롤러가 Authorization 헤더에서 엉뚱한 tenant 를 뽑아 넘기거나 인증을 아예 안 거는 배선 실수는
 * HTTP 경계에서만 잡히고, 그건 남의 조직 데이터가 새느냐의 문제다.
 *
 * <p>ClickHouse 와 DNS 는 둘 다 대역으로 바꾼다. 실시간 조회가 진짜 네트워크를 타면 테스트가
 * 환경에 따라 흔들린다.
 */
@SpringBootTest
@AutoConfigureMockMvc
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.ANY)
@TestPropertySource(properties = "spring.kafka.listener.auto-startup=false")
class CorrelateApiIntegrationTest {

    private static final long T = 1_700_000_000_000L;

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper om;

    @MockitoBean
    private ClickHouseReader reader;

    @MockitoBean
    private DnsResolver dns;

    private List<Map<String, Object>> seedRows = List.of();
    private List<Map<String, Object>> connectRows = List.of();
    private final List<ClickHouseQuery> queries = new ArrayList<>();

    @BeforeEach
    void routeStubs() {
        queries.clear();
        seedRows = List.of(dnsRow("mac-1", T, "example.com", "", "93.184.216.34"));
        connectRows = List.of(connectRow("mac-1", T + 120, "93.184.216.34", "firefox"));
        when(reader.query(any())).thenAnswer(inv -> {
            ClickHouseQuery q = inv.getArgument(0);
            queries.add(q);
            // 보정 후보 조회만 dest_ip IN (...) 을 쓴다. 기준점 조회와 이걸로 가른다.
            return q.sql().contains("dest_ip IN (") ? connectRows : seedRows;
        });
        when(dns.forward(any())).thenReturn(ForwardLookup.ok(List.of("93.184.216.34")));
        when(dns.reverse(any())).thenReturn(ReverseLookup.ok(List.of("ptr.example.com")));
    }

    // --- 인증 ---

    @Test
    void correlate_는_토큰_없으면_401() throws Exception {
        mvc.perform(get("/api/intelligence/correlate").param("target", "example.com"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void dns_lookup_은_토큰_없으면_401() throws Exception {
        mvc.perform(get("/api/intelligence/dns-lookup").param("target", "example.com"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void 인증_전에는_외부에도_묻지_않고_조회도_안_한다() throws Exception {
        mvc.perform(get("/api/intelligence/dns-lookup").param("target", "example.com"))
                .andExpect(status().isUnauthorized());

        verify(dns, never()).forward(any());
        assertTrue(queries.isEmpty(), "인증 실패면 ClickHouse 조회도 없어야 한다");
    }

    // --- tenant 격리 ---

    @Test
    void 모든_관측_조회가_로그인_유저의_tenant_로만_격리된다() throws Exception {
        String[] a = signup("a-corr@edrdog.com");
        String[] b = signup("b-corr@edrdog.com");

        mvc.perform(get("/api/intelligence/correlate")
                        .param("target", "example.com")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk());

        assertEquals(2, queries.size(), "기준점 조회 + 보정 후보 조회");
        for (ClickHouseQuery q : queries) {
            assertEquals(a[1], q.params().get("tenant"), q.sql());
            assertFalse(q.params().containsValue(b[1]), "다른 tenant 값이 조회에 섞이면 안 된다: " + q.sql());
            assertTrue(q.sql().contains("tenant_id = {tenant:String}"), q.sql());
        }
    }

    @Test
    void 같은_요청이라도_토큰이_다르면_다른_tenant_로_조회한다() throws Exception {
        String[] a = signup("a-corr2@edrdog.com");
        String[] b = signup("b-corr2@edrdog.com");

        mvc.perform(get("/api/intelligence/correlate").param("target", "example.com")
                .header("Authorization", "Bearer " + a[0])).andExpect(status().isOk());
        String tenantOfA = queries.get(0).params().get("tenant");

        queries.clear();
        mvc.perform(get("/api/intelligence/correlate").param("target", "example.com")
                .header("Authorization", "Bearer " + b[0])).andExpect(status().isOk());
        String tenantOfB = queries.get(0).params().get("tenant");

        assertEquals(a[1], tenantOfA);
        assertEquals(b[1], tenantOfB);
        assertFalse(tenantOfA.equals(tenantOfB), "두 조직이 같은 tenant 로 조회되면 격리가 없는 것이다");
    }

    // --- 입력 검증 ---

    @Test
    void 도메인도_IP_도_아니면_400() throws Exception {
        String[] a = signup("a-corrbad@edrdog.com");

        for (String bad : List.of("not a domain", "http://example.com", "example.com;ls", "*.example.com")) {
            mvc.perform(get("/api/intelligence/correlate").param("target", bad)
                            .header("Authorization", "Bearer " + a[0]))
                    .andExpect(status().isBadRequest());
            mvc.perform(get("/api/intelligence/dns-lookup").param("target", bad)
                            .header("Authorization", "Bearer " + a[0]))
                    .andExpect(status().isBadRequest());
        }
    }

    @Test
    void 형식이_틀리면_외부에_묻지도_조회하지도_않는다() throws Exception {
        String[] a = signup("a-corrbad2@edrdog.com");

        mvc.perform(get("/api/intelligence/correlate").param("target", "not a domain")
                .header("Authorization", "Bearer " + a[0])).andExpect(status().isBadRequest());

        verify(dns, never()).forward(any());
        assertTrue(queries.isEmpty(), "검증에 걸린 값으로 조회를 보내면 안 된다");
    }

    // --- 조회 실패 격리 ---

    @Test
    void 실시간_DNS_가_실패해도_관측_그래프는_200_으로_나온다() throws Exception {
        String[] a = signup("a-corrfail@edrdog.com");
        when(dns.forward(any())).thenReturn(ForwardLookup.failed("java.net.SocketTimeoutException"));

        mvc.perform(get("/api/intelligence/correlate").param("target", "example.com")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.observedEvents").value(1))
                .andExpect(jsonPath("$.liveDns.forward.status").value("FAILED"))
                .andExpect(jsonPath("$.edges[?(@.origin=='OBSERVED')]").isNotEmpty())
                .andExpect(jsonPath("$.edges[?(@.origin=='LIVE_DNS')]").isEmpty());
    }

    @Test
    void 실시간_DNS_가_터져도_500_이_아니다() throws Exception {
        // 구현은 예외를 안 던지기로 되어 있지만, 그 계약이 깨져도 화면 전체가 죽지는 않아야 한다는 뜻은 아니다.
        // 여기서는 조회 실패가 상태값으로 내려온다는 것까지만 보장한다.
        String[] a = signup("a-corrfail2@edrdog.com");
        when(dns.forward(any())).thenReturn(ForwardLookup.failed("timeout"));

        mvc.perform(get("/api/intelligence/dns-lookup").param("target", "example.com")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.forward.status").value("FAILED"))
                .andExpect(jsonPath("$.forward.error").value("timeout"));
    }

    @Test
    void liveDns_를_끄면_외부에_묻지_않는다() throws Exception {
        String[] a = signup("a-corroff@edrdog.com");

        mvc.perform(get("/api/intelligence/correlate")
                        .param("target", "example.com").param("liveDns", "false")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.liveDns").doesNotExist());

        verify(dns, never()).forward(any());
    }

    // --- 응답 내용 ---

    @Test
    void 관측과_추론과_실시간을_출처로_구분해_준다() throws Exception {
        String[] a = signup("a-corrgraph@edrdog.com");

        mvc.perform(get("/api/intelligence/correlate").param("target", "example.com")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.target.kind").value("DOMAIN"))
                .andExpect(jsonPath("$.target.value").value("example.com"))
                // 관측: DNS 응답이 준 IP
                .andExpect(jsonPath("$.edges[?(@.relation=='RESOLVED_TO' && @.origin=='OBSERVED')].to")
                        .value("ip:93.184.216.34"))
                // 추론: 프로세스가 비어 온 DNS 를 되짚어 찾은 질의자. 근거가 같이 나온다.
                .andExpect(jsonPath("$.edges[?(@.origin=='INFERRED')].from").value("process:firefox"))
                .andExpect(jsonPath("$.edges[?(@.origin=='INFERRED')].basis").isNotEmpty())
                // 실시간: 뒷받침하는 관측이 없으므로 횟수가 0 이다
                .andExpect(jsonPath("$.edges[?(@.origin=='LIVE_DNS')].observations").value(0));
    }

    @Test
    void PTR_은_후보로만_주고_원본_IP_를_대체하지_않는다() throws Exception {
        String[] a = signup("a-corrptr@edrdog.com");
        seedRows = List.of();
        connectRows = List.of();

        mvc.perform(get("/api/intelligence/correlate").param("target", "93.184.216.34")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.nodes[?(@.id=='ip:93.184.216.34')].kind").value("IP"))
                .andExpect(jsonPath("$.nodes[?(@.kind=='PTR_NAME')].value").value("ptr.example.com"))
                // 같은 이름이 관측 도메인 노드로 둔갑하면 안 된다.
                .andExpect(jsonPath("$.nodes[?(@.id=='domain:ptr.example.com')]").isEmpty())
                .andExpect(jsonPath("$.edges[?(@.relation=='PTR_CANDIDATE')].origin").value("LIVE_DNS"));
    }

    @Test
    void IP_대상은_역방향만_묻는다() throws Exception {
        String[] a = signup("a-corrrev@edrdog.com");

        mvc.perform(get("/api/intelligence/dns-lookup").param("target", "93.184.216.34")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.target.kind").value("IP"))
                .andExpect(jsonPath("$.forward").doesNotExist())
                .andExpect(jsonPath("$.reverse.ptrNames[0]").value("ptr.example.com"));

        verify(dns, never()).forward(any());
    }

    @Test
    void 관측이_없어도_기준점과_실시간_결과는_준다() throws Exception {
        String[] a = signup("a-corrempty@edrdog.com");
        seedRows = List.of();
        connectRows = List.of();

        mvc.perform(get("/api/intelligence/correlate").param("target", "example.com")
                        .header("Authorization", "Bearer " + a[0]))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.observedEvents").value(0))
                .andExpect(jsonPath("$.nodes[?(@.id=='domain:example.com')]").isNotEmpty())
                .andExpect(jsonPath("$.edges[?(@.origin=='OBSERVED')]").isEmpty());
    }

    // --- 도우미 ---

    private String[] signup(String email) throws Exception {
        MvcResult res = mvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"password1\"}"))
                .andExpect(status().isCreated())
                .andReturn();
        var node = om.readTree(res.getResponse().getContentAsString());
        return new String[]{node.get("token").asText(), node.get("tenantId").asText()};
    }

    private static Map<String, Object> dnsRow(String host, long ts, String domain, String process, String answer) {
        Map<String, Object> row = baseRow(host, "dns", ts, process);
        row.put("domain", domain);
        row.put("detail", "{\"queryType\":\"A\",\"answers\":[\"" + answer + "\"]}");
        return row;
    }

    private static Map<String, Object> connectRow(String host, long ts, String destIp, String process) {
        Map<String, Object> row = baseRow(host, "network", ts, process);
        row.put("dest_ip", destIp);
        return row;
    }

    private static Map<String, Object> baseRow(String host, String type, long ts, String process) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("host", host);
        row.put("type", type);
        row.put("ts", ts);
        row.put("process", process);
        row.put("parent", "");
        row.put("cmdline", "");
        row.put("dest_ip", "");
        row.put("dest_port", 0);
        row.put("domain", "");
        row.put("detail", "{}");
        row.put("sha256", "");
        row.put("ingested_at", "");
        return row;
    }
}
