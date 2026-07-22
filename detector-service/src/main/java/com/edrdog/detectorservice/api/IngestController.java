package com.edrdog.detectorservice.api;

import com.edrdog.detectorservice.dto.Alert;
import com.edrdog.detectorservice.dto.Event;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * 데모용 이벤트 발행/조회 REST. Swagger UI(/swagger-ui.html)에서 호출하면
 * events 발행 → detector 상관분석 → alerts → (responder 권장조치) 흐름을 눈으로 확인할 수 있다.
 */
@RestController
@RequestMapping("/api")
@Tag(name = "ingest", description = "이벤트 발행 및 판정 결과 조회 (데모)")
public class IngestController {

    private final EventProducer producer;
    private final RecentAlerts recentAlerts;

    public IngestController(EventProducer producer, RecentAlerts recentAlerts) {
        this.producer = producer;
        this.recentAlerts = recentAlerts;
    }

    @Operation(summary = "이벤트 1건 발행", description = "임의 이벤트를 events 토픽으로 발행한다. 단일 이벤트는 보통 alert 를 만들지 않는다(시퀀스 필요).")
    @PostMapping("/events")
    public ResponseEntity<Event> publish(@RequestBody Event event) {
        producer.publish(event);
        return ResponseEntity.accepted().body(event);
    }

    @Operation(summary = "공격 시나리오 발행",
            description = "룰을 확실히 트리거하는 2-이벤트 시퀀스를 발행한다. name: process-chain(T1059/HIGH) 또는 download-exec(T1105/CRITICAL). "
                    + "tenantId 는 로그인 tenant 의 PK(GET /api/auth/me 의 tenantId, 예: 1)여야 해당 tenant 로 alert 조회/Slack 이 도달한다.")
    @PostMapping("/events/scenario/{name}")
    public ResponseEntity<Map<String, Object>> publishScenario(
            @PathVariable String name,
            @RequestParam(defaultValue = "demo-host-01") String host,
            @RequestParam String tenantId) {
        if (!Scenarios.isSupported(name)) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "미지원 시나리오: " + name,
                    "supported", List.of(Scenarios.PROCESS_CHAIN, Scenarios.DOWNLOAD_EXEC)));
        }
        if (!TenantIds.isValidPk(tenantId)) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "tenantId 는 tenant PK(양의 정수)여야 합니다: " + tenantId,
                    "hint", "회원가입/로그인 후 GET /api/auth/me 의 tenantId 를 사용하세요"));
        }
        // 발행 시각 기준으로 윈도우 안 시퀀스 생성 (판정은 이벤트 ts 필드로 상관)
        long baseTs = System.currentTimeMillis();
        List<Event> events = Scenarios.build(name, host, baseTs, tenantId);
        events.forEach(producer::publish);
        return ResponseEntity.accepted().body(Map.of(
                "scenario", name,
                "host", host,
                "tenantId", tenantId,
                "published", events,
                "hint", "GET /api/alerts/recent 로 권장조치 확인 (전파에 약간의 지연)"));
    }

    @Operation(summary = "최근 판정 결과 조회", description = "detector 가 발행한 최근 alert 목록. action 필드가 권장조치(notify/kill/isolate).")
    @GetMapping("/alerts/recent")
    public List<Alert> recentAlerts() {
        return recentAlerts.list();
    }
}
