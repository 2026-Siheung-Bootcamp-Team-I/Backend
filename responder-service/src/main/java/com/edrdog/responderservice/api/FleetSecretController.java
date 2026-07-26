package com.edrdog.responderservice.api;

import com.edrdog.responderservice.fleet.FleetClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Fleet enroll secret 조회. 온보딩의 "기기를 Fleet 에 등록" 안내가 이 값을 필요로 한다.
 *
 * <p>responder 는 클러스터 안에서만 열리고 앱 인증이 없다. 바깥 노출은 api-service 가 Bearer 로
 * 인증한 뒤 프록시하는 경로 하나뿐이다(kill 과 같은 구조).
 */
@RestController
@RequestMapping("/api/responder/fleet")
public class FleetSecretController {

    private static final Logger log = LoggerFactory.getLogger(FleetSecretController.class);

    private final FleetClient fleet;

    public FleetSecretController(FleetClient fleet) {
        this.fleet = fleet;
    }

    /**
     * Fleet enroll secret. Fleet 이 죽어 있거나 토큰이 만료면 500 대신 값 없음으로 답한다.
     * 화면은 "값을 가져오지 못함"을 안내하면 되고, 조회 실패가 온보딩 전체를 깨뜨릴 이유는 없다.
     */
    @GetMapping("/enroll-secret")
    public FleetEnrollSecret enrollSecret() {
        try {
            return new FleetEnrollSecret(fleet.enrollSecret());
        } catch (RuntimeException e) {
            log.error("Fleet enroll secret 조회 실패 err={}", e.toString());
            return new FleetEnrollSecret(null);
        }
    }

    /** 조회 응답. 값이 없으면 secret 이 null 이다. */
    public record FleetEnrollSecret(String secret) {
    }
}
