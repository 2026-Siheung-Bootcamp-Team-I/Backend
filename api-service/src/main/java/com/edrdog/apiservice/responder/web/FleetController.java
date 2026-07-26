package com.edrdog.apiservice.responder.web;

import com.edrdog.apiservice.auth.service.AuthService;
import com.edrdog.apiservice.responder.ResponderClient;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Fleet 연동 값 조회. 지금은 온보딩 안내에 넣을 enroll secret 하나뿐이다.
 *
 * <p>인증은 세션 Bearer + 프론트 X-API-Key 둘 다 요구한다(면제 경로에 넣지 않는다).
 * Fleet 은 인스턴스가 하나라 이 값에는 tenant 구분이 없다. 로그인한 사람에게만 보여준다.
 */
@RestController
@RequestMapping("/api/fleet")
@Tag(name = "fleet", description = "Fleet 연동 값 조회 (온보딩 안내용)")
public class FleetController {

    private static final String BEARER_PREFIX = "Bearer ";

    private final ResponderClient responder;
    private final AuthService auth;

    public FleetController(ResponderClient responder, AuthService auth) {
        this.responder = responder;
        this.auth = auth;
    }

    @Operation(summary = "Fleet enroll secret 조회",
            description = "fleetd 패키지를 만들 때 쓰는 Fleet 자체 enroll secret. tenant 별 EDRdog enroll secret 과 다른 값이다. "
                    + "Fleet 이 응답하지 않으면 secret 이 null 이다.")
    @GetMapping("/enroll-secret")
    public FleetEnrollSecretResponse enrollSecret(
            @RequestHeader(name = "Authorization", required = false) String authorization) {
        auth.resolve(bearerToken(authorization));   // 로그인하지 않았으면 여기서 401
        return new FleetEnrollSecretResponse(responder.fleetEnrollSecret());
    }

    /** "Bearer " 접두어를 떼서 토큰만 반환. 없으면 null. */
    private static String bearerToken(String authorization) {
        if (authorization == null || !authorization.startsWith(BEARER_PREFIX)) {
            return null;
        }
        return authorization.substring(BEARER_PREFIX.length()).trim();
    }

    /** 조회 응답. Fleet 이 값을 주지 못하면 secret 이 null 이다. */
    public record FleetEnrollSecretResponse(String secret) {
    }
}
