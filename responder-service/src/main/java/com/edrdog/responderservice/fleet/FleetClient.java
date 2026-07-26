package com.edrdog.responderservice.fleet;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
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

    /**
     * 호스트 식별자(hostname/uuid)로 Fleet 내부 id 와 플랫폼을 조회한다.
     * 플랫폼이 필요한 이유는 Fleet 이 Windows 에 PowerShell, 그 외에 sh 를 실행하기 때문이다.
     */
    public FleetHost resolveHost(String identifier) {
        // Fleet 조회는 대소문자를 구분한다. 알림의 host 는 osquery 가 준 원본이라 Fleet 저장값과
        // 다를 수 있어(macOS 실측: 원본 404, 소문자 200) 후보를 순서대로 시도한다.
        for (String candidate : HostIdentifiers.candidates(identifier)) {
            try {
                HostIdentifierResponse res = http.get()
                        .uri("/api/v1/fleet/hosts/identifier/{id}", candidate)
                        .retrieve()
                        .body(HostIdentifierResponse.class);
                if (res != null && res.host() != null) {
                    return new FleetHost(res.host().id(), res.host().platform());
                }
            } catch (HttpClientErrorException.NotFound e) {
                // 다음 후보로 넘어간다. 후보를 다 소진하면 아래에서 실패로 처리한다.
            }
        }
        throw new IllegalStateException("Fleet 에서 호스트를 찾지 못함: " + identifier);
    }

    /**
     * Fleet 자체 enroll secret(fleetd 패키지 빌드용). 없거나 형태가 어긋나면 null.
     *
     * <p>온보딩 안내가 "관리자에게 문의"로 끊기지 않도록 서버가 대신 읽어준다. 조치(kill)를 쓰려면
     * 기기를 Fleet 에 등록해야 하는데, 그 값을 보려고 Fleet 콘솔 계정을 따로 받아야 했다.
     */
    public String enrollSecret() {
        FleetEnrollSecretResponse res = http.get()
                .uri("/api/v1/fleet/spec/enroll_secret")
                .retrieve()
                .body(FleetEnrollSecretResponse.class);
        return res == null ? null : res.first();
    }

    /** 스크립트를 호스트에서 동기 실행하고 결과를 반환. */
    public FleetScriptResult runScriptSync(int hostId, String scriptContents) {
        return http.post()
                .uri("/api/v1/fleet/scripts/run/sync")
                .body(Map.of("host_id", hostId, "script_contents", scriptContents))
                .retrieve()
                .body(FleetScriptResult.class);
    }

    /** GET hosts/identifier 응답의 필요한 부분만. 나머지 필드는 무시된다. */
    private record HostIdentifierResponse(Host host) {
        private record Host(int id, String platform) {
        }
    }
}
