package com.edrdog.responderservice.fleet;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

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
 */
@Component
public class FleetClient {

    private final RestClient http;

    public FleetClient(@Value("${edrdog.fleet.base-url}") String baseUrl,
                       @Value("${edrdog.fleet.token}") String token) {
        this.http = RestClient.builder()
                .baseUrl(baseUrl)
                .defaultHeader("Authorization", "Bearer " + token)
                .build();
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
