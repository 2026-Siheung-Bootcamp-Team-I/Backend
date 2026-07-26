package com.edrdog.responderservice.fleet;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Fleet enroll secret 응답에서 쓸 값을 고르는 규칙.
 *
 * <p>Fleet 은 secret 을 여러 개 둘 수 있다(회전 중에는 옛것과 새것이 함께 산다).
 * 온보딩 안내에 넣을 값은 하나뿐이라 첫 번째를 쓴다. 형태가 어긋나면 값이 아니라 없음으로 답해야
 * 화면이 잘못된 secret 을 명령어에 박아 넣지 않는다.
 */
class FleetEnrollSecretResponseTest {

    @Test
    @DisplayName("secret 이 여럿이면 첫 번째를 쓴다")
    void picksFirstSecret() {
        FleetEnrollSecretResponse res = response(
                new FleetEnrollSecretResponse.Secret("first"),
                new FleetEnrollSecretResponse.Secret("second"));

        assertThat(res.first()).isEqualTo("first");
    }

    @Test
    @DisplayName("secret 목록이 비어 있으면 없음")
    void emptyList_isNull() {
        assertThat(response().first()).isNull();
    }

    @Test
    @DisplayName("spec 이 없으면 없음")
    void missingSpec_isNull() {
        assertThat(new FleetEnrollSecretResponse(null).first()).isNull();
    }

    @Test
    @DisplayName("secrets 가 없으면 없음")
    void missingSecrets_isNull() {
        assertThat(new FleetEnrollSecretResponse(new FleetEnrollSecretResponse.Spec(null)).first())
                .isNull();
    }

    @Test
    @DisplayName("첫 값이 비어 있으면 없음으로 본다(빈 문자열을 명령어에 박지 않는다)")
    void blankSecret_isNull() {
        assertThat(response(new FleetEnrollSecretResponse.Secret("  ")).first()).isNull();
    }

    private static FleetEnrollSecretResponse response(FleetEnrollSecretResponse.Secret... secrets) {
        return new FleetEnrollSecretResponse(new FleetEnrollSecretResponse.Spec(List.of(secrets)));
    }
}
