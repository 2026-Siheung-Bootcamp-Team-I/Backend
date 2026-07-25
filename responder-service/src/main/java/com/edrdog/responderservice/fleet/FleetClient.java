package com.edrdog.responderservice.fleet;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.InputStream;
import java.net.http.HttpClient;
import java.security.KeyStore;
import java.util.Map;

/**
 * Fleet REST API 호출 래퍼. 자체 엔드포인트 에이전트를 만들지 않고 Fleet 의 스크립트 실행 기능을 통해
 * 등록된 호스트에서 조치 스크립트를 실행한다.
 *
 * 사용 엔드포인트:
 * - GET  /api/v1/fleet/hosts/identifier/{identifier} : 호스트 식별자 → Fleet host id
 * - POST /api/v1/fleet/scripts/run/sync              : 스크립트 동기 실행(결과까지 대기)
 *
 * 지연 특성: Fleet 은 push 가 아니라 fleetd 폴링이라 sync 호출도 폴링 한 주기만큼 걸릴 수 있다(수초~수십초).
 *
 * 전송 보안: Bearer 토큰을 싣기 때문에 실제 조치가 켜진 경우 https 를 강제한다(FleetTls). 인증서 검증은
 * 기본적으로 시스템 신뢰저장소를 쓰고, Fleet 이 자가서명 인증서면 edrdog.fleet.tls.truststore 로 신뢰할
 * 인증서를 지정한다.
 */
@Component
public class FleetClient {

    private final RestClient http;

    public FleetClient(@Value("${edrdog.fleet.base-url}") String baseUrl,
                       @Value("${edrdog.fleet.token}") String token,
                       @Value("${edrdog.responder.execute.enabled}") boolean executeEnabled,
                       @Value("${edrdog.fleet.tls.truststore:}") String truststore,
                       @Value("${edrdog.fleet.tls.truststore-password:}") String truststorePassword,
                       @Value("${edrdog.fleet.tls.truststore-type:PKCS12}") String truststoreType) {
        FleetTls.requireHttpsWhenExecuting(baseUrl, executeEnabled);
        this.http = RestClient.builder()
                .baseUrl(baseUrl)
                .defaultHeader("Authorization", "Bearer " + token)
                .requestFactory(new JdkClientHttpRequestFactory(
                        httpClient(truststore, truststorePassword, truststoreType)))
                .build();
    }

    /** truststore 가 지정되면 그 인증서만 신뢰하는 HttpClient, 아니면 시스템 신뢰저장소를 쓰는 기본 HttpClient. */
    private static HttpClient httpClient(String truststore, String password, String type) {
        HttpClient.Builder builder = HttpClient.newBuilder();
        if (truststore != null && !truststore.isBlank()) {
            builder.sslContext(trustContext(truststore, password, type));
        }
        return builder.build();
    }

    /** 지정한 truststore 로 Fleet 서버 인증서를 검증하는 SSLContext 를 만든다. */
    private static SSLContext trustContext(String location, String password, String type) {
        try {
            KeyStore ks = KeyStore.getInstance(type == null || type.isBlank() ? "PKCS12" : type);
            try (InputStream in = openTruststore(location)) {
                ks.load(in, password == null ? new char[0] : password.toCharArray());
            }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, tmf.getTrustManagers(), null);
            return ctx;
        } catch (Exception e) {
            throw new IllegalStateException("Fleet TLS truststore 로드 실패: " + location, e);
        }
    }

    /** classpath: 접두어면 클래스패스 리소스로, 아니면 파일 경로로 truststore 를 연다. */
    private static InputStream openTruststore(String location) throws Exception {
        return location.startsWith("classpath:")
                ? new ClassPathResource(location.substring("classpath:".length())).getInputStream()
                : new FileSystemResource(location).getInputStream();
    }

    /** 호스트 식별자(hostname/uuid)를 Fleet 내부 host id 로 변환. */
    public int resolveHostId(String identifier) {
        HostIdentifierResponse res = http.get()
                .uri("/api/v1/fleet/hosts/identifier/{id}", identifier)
                .retrieve()
                .body(HostIdentifierResponse.class);
        if (res == null || res.host() == null) {
            throw new IllegalStateException("Fleet 에서 호스트를 찾지 못함: " + identifier);
        }
        return res.host().id();
    }

    /** 스크립트를 호스트에서 동기 실행하고 결과를 반환. */
    public FleetScriptResult runScriptSync(int hostId, String scriptContents) {
        return http.post()
                .uri("/api/v1/fleet/scripts/run/sync")
                .body(Map.of("host_id", hostId, "script_contents", scriptContents))
                .retrieve()
                .body(FleetScriptResult.class);
    }

    /** GET hosts/identifier 응답의 필요한 부분만. */
    private record HostIdentifierResponse(Host host) {
        private record Host(int id) {
        }
    }
}
