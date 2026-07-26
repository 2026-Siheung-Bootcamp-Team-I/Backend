package com.edrdog.responderservice.fleet;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * {@code GET /api/v1/fleet/spec/enroll_secret} 응답 중 필요한 부분만.
 *
 * <p>이 값은 EDRdog enroll secret 과 다른 것이다. fleetd 패키지를 만들 때 쓰는 Fleet 자체 값이고,
 * 원래는 Fleet 콘솔이나 {@code fleetctl get enroll-secret} 으로 봐야 한다. 그러려면 Fleet 계정이
 * 필요해서 온보딩이 "관리자에게 문의"로 끊긴다. 서버가 이미 Fleet 관리자 토큰을 들고 있으니
 * 대신 읽어다 준다.
 *
 * <p>{@code created_at} 같은 나머지 필드는 쓰지 않으므로 무시한다.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record FleetEnrollSecretResponse(Spec spec) {

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Spec(List<Secret> secrets) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Secret(String secret) {
    }

    /**
     * 안내에 넣을 enroll secret. 회전 중이면 여러 개일 수 있는데 안내에는 하나만 들어가므로
     * 첫 번째를 쓴다. 응답 형태가 어긋나거나 값이 비면 null 이다(빈 값을 명령어에 박지 않는다).
     */
    public String first() {
        if (spec == null || spec.secrets() == null || spec.secrets().isEmpty()) {
            return null;
        }
        Secret head = spec.secrets().get(0);
        if (head == null || head.secret() == null || head.secret().isBlank()) {
            return null;
        }
        return head.secret();
    }
}
