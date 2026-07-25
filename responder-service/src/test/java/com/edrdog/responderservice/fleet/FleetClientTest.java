package com.edrdog.responderservice.fleet;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * FleetClient 생성 시 전송 보안 배선 검증.
 * 순수 판단(FleetTls)은 FleetTlsTest 에서 다루고, 여기서는 truststore 로딩·https 강제가
 * 생성자에서 실제로 걸리는지(보안 실패는 부팅에서 걸러야 한다) 확인한다.
 */
class FleetClientTest {

    @Test
    @DisplayName("실행 스위치 ON + http base-url 이면 생성 자체가 막힌다(평문 토큰 노출 차단)")
    void executingOverHttp_failsFast() {
        assertThatThrownBy(() -> new FleetClient(
                "http://localhost:8080", "tok", true, "", "", "PKCS12"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("https");
    }

    @Test
    @DisplayName("지정한 truststore 를 찾지 못하면 경로를 담은 IllegalStateException 으로 실패한다")
    void missingTruststore_throwsWithLocation() {
        String location = "/no/such/fleet-truststore.p12";
        assertThatThrownBy(() -> new FleetClient(
                "https://fleet.example", "tok", false, location, "", "PKCS12"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining(location);
    }

    @Test
    @DisplayName("truststore 미지정이면 시스템 신뢰저장소로 정상 생성된다")
    void noTruststore_buildsWithSystemTrust() {
        assertThatCode(() -> new FleetClient(
                "https://fleet.example", "tok", false, "", "", "PKCS12"))
                .doesNotThrowAnyException();
    }
}
