package com.edrdog.apiservice.collector;

import com.edrdog.apiservice.host.EnrolledHost;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * collector 내부 API 호출 계약 검증(경로·tenant 파라미터·X-Internal-Key·응답 매핑)과 실패 시 fail-soft.
 * 가짜 HTTP 서버를 띄워 collector 없이 확인한다.
 */
class CollectorClientTest {

    private static final String KEY = "test-internal-key";

    private HttpServer server;
    private String requestUri;
    private String sentKey;
    private String responseBody = "[]";
    private int responseStatus = 200;

    @BeforeEach
    void startServer() throws IOException {
        requestUri = null;
        sentKey = null;
        responseBody = "[]";
        responseStatus = 200;
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            requestUri = exchange.getRequestURI().toString();
            sentKey = exchange.getRequestHeaders().getFirst("X-Internal-Key");
            byte[] body = responseBody.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(responseStatus, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    private CollectorClient client() {
        return new CollectorClient("http://127.0.0.1:" + server.getAddress().getPort(), KEY);
    }

    @Test
    void 등록_노드를_tenant_로_조회해_EnrolledHost_로_매핑한다() {
        responseBody = "[{\"host\":\"HOST-1\",\"lastSeenAt\":1730000000000,\"platform\":\"darwin\"}]";

        List<EnrolledHost> hosts = client().enrolledHosts(1L);

        assertEquals(List.of(new EnrolledHost("HOST-1", 1730000000000L, "darwin")), hosts);
        assertEquals("/api/internal/nodes?tenantId=1", requestUri);
        assertEquals(KEY, sentKey);
    }

    @Test
    void collector_가_오류를_주면_빈_목록이다() {
        // 등록 정보를 못 받는 것보다 호스트 목록 화면 전체가 500 으로 죽는 쪽이 더 나쁘다.
        responseStatus = 500;
        responseBody = "boom";

        assertTrue(client().enrolledHosts(1L).isEmpty());
    }

    @Test
    void collector_가_죽어있으면_빈_목록이다() {
        server.stop(0);

        assertTrue(client().enrolledHosts(1L).isEmpty());
    }
}
