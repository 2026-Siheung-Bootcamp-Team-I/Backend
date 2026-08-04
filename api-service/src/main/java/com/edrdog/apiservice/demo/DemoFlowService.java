package com.edrdog.apiservice.demo;

import com.edrdog.apiservice.alert.AlertId;
import com.edrdog.apiservice.alert.AlertService;
import com.edrdog.apiservice.alert.web.AlertResponse;
import com.edrdog.apiservice.auth.AuthException;
import com.edrdog.apiservice.demo.web.DemoFlowResponse;
import com.edrdog.schema.Event;
import com.edrdog.apiservice.demo.web.DemoFlowStep;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * 발표용 전체 플로우 실행. 엔드포인트가 로그를 보낸 것처럼 events 토픽에 발행하고,
 * detector 가 alerts 토픽으로 되돌려준 판정이 저장돼 조회 가능해질 때까지 기다린 뒤 단계별 결과를 만든다.
 * 수집/탐지({@link AlertArrivals} 관측)/저장 세 단계를 각각 실측한다.
 *
 * <p>alert id 는 발행 <b>전에</b> 계산한다. 발행 후에 조회로 찾으면 과거 회차의 같은 룰 alert 를 이번 결과로 집는다.
 */
@Service
public class DemoFlowService {

    private static final Logger log = LoggerFactory.getLogger(DemoFlowService.class);

    private static final long POLL_MS = 250;

    private static final String PIPELINE =
            "api-service → Kafka(events) → detector Kafka Streams → Kafka(alerts) → api-service(ClickHouse+MySQL)";

    private final EventsProducer producer;
    private final AlertArrivals arrivals;
    private final AlertService alerts;
    private final long detectTimeoutMs;
    private final long storeTimeoutMs;

    public DemoFlowService(EventsProducer producer, AlertArrivals arrivals, AlertService alerts,
                           @Value("${edrdog.demo.detect-timeout-ms}") long detectTimeoutMs,
                           @Value("${edrdog.demo.store-timeout-ms}") long storeTimeoutMs) {
        this.producer = producer;
        this.arrivals = arrivals;
        this.alerts = alerts;
        this.detectTimeoutMs = detectTimeoutMs;
        this.storeTimeoutMs = storeTimeoutMs;
    }

    /**
     * 시나리오 로그를 발행하고 판정이 조회 가능해질 때까지 기다린다.
     *
     * @param scenario 시나리오 이름 (미지원이면 IllegalArgumentException)
     * @param host     엔드포인트 식별자. null/빈값이면 시나리오 기본 host
     * @param tenantId 로그인 유저의 tenant PK 문자열
     */
    public DemoFlowResponse run(String scenario, String host, String tenantId) {
        String target = (host == null || host.isBlank()) ? DemoScenario.defaultHost(scenario) : host.trim();
        long start = System.currentTimeMillis();
        List<Event> logs = DemoScenario.build(scenario, target, start, tenantId);

        logs.forEach(producer::publish);
        long publishedAt = System.currentTimeMillis();

        String ruleId = DemoScenario.expectedRuleId(scenario);
        long triggerTs = logs.get(logs.size() - 1).getTs();
        String alertId = AlertId.of(tenantId, target, ruleId, triggerTs);

        Optional<Long> detectedAt = awaitArrival(alertId, publishedAt + detectTimeoutMs);
        Optional<AlertResponse> stored = detectedAt.isEmpty()
                ? Optional.empty()
                : awaitStored(tenantId, alertId, System.currentTimeMillis() + storeTimeoutMs);
        long finishedAt = System.currentTimeMillis();

        List<DemoFlowStep> steps = steps(logs, ruleId, start, publishedAt, detectedAt, stored, finishedAt);
        if (stored.isEmpty()) {
            log.warn("데모 플로우 미완료: scenario={} host={} alertId={} 탐지도착={} (detector/Kafka 상태 확인)",
                    scenario, target, alertId, detectedAt.isPresent());
        }
        return new DemoFlowResponse(scenario, target, tenantId, PIPELINE, alertId,
                finishedAt - start, steps, logs, stored.orElse(null), nextSteps(alertId));
    }

    private List<DemoFlowStep> steps(List<Event> logs, String ruleId, long start, long publishedAt,
                                     Optional<Long> detectedAt, Optional<AlertResponse> stored, long finishedAt) {
        List<DemoFlowStep> steps = new ArrayList<>();
        long normal = logs.stream().filter(e -> e.getTs() < start).count();
        steps.add(DemoFlowStep.ok(1, "수집", "api-service → Kafka(events)", publishedAt - start,
                "엔드포인트 로그 " + logs.size() + "건 발행 (평소 배경 " + normal + "건 + 공격 "
                        + (logs.size() - normal) + "건). 파티션 키 = host 라 순서가 보존된다"));

        String detectPath = "Kafka(events) → detector Kafka Streams → Kafka(alerts)";
        if (detectedAt.isEmpty()) {
            steps.add(DemoFlowStep.timeout(2, "탐지", detectPath, finishedAt - publishedAt,
                    detectTimeoutMs + "ms 안에 판정이 alerts 토픽으로 돌아오지 않았다. "
                            + "detector-service 파드와 Kafka 연결을 확인하세요"));
            return List.copyOf(steps);
        }
        steps.add(DemoFlowStep.ok(2, "탐지", detectPath, detectedAt.get() - publishedAt,
                "상관분석이 " + ruleId + " 를 매칭해 alerts 토픽으로 발행, api-service 가 되받았다"));

        String storePath = "api-service → ClickHouse(판정기록) + MySQL(트리아지 status)";
        if (stored.isEmpty()) {
            steps.add(DemoFlowStep.timeout(3, "저장", storePath, finishedAt - detectedAt.get(),
                    storeTimeoutMs + "ms 안에 조회되지 않았다. ClickHouse 상태를 확인하세요"));
            return List.copyOf(steps);
        }
        AlertResponse alert = stored.get();
        steps.add(DemoFlowStep.ok(3, "저장", storePath, finishedAt - detectedAt.get(),
                alert.threatName() + " / " + alert.mitre() + " / " + alert.severity()
                        + " → 권고조치 " + alert.action() + ". GET /api/alerts 로 조회된다"));
        return List.copyOf(steps);
    }

    /** 그 alert 가 alerts 토픽에 도착할 때까지 폴링. 제한시간을 넘기면 empty. */
    private Optional<Long> awaitArrival(String alertId, long deadline) {
        while (true) {
            Optional<Long> at = arrivals.arrivedAt(alertId);
            if (at.isPresent() || !sleepUntil(deadline)) {
                return at;
            }
        }
    }

    /** 그 alert 가 조회 가능해질 때까지 폴링. 제한시간을 넘기면 empty. */
    private Optional<AlertResponse> awaitStored(String tenantId, String alertId, long deadline) {
        while (true) {
            try {
                return Optional.of(alerts.get(tenantId, alertId));
            } catch (AuthException e) {
                if (e.getKind() != AuthException.Kind.NOT_FOUND || !sleepUntil(deadline)) {
                    return Optional.empty();   // 아직 적재 전(404) 이 아니면 재시도할 이유가 없다
                }
            }
        }
    }

    /** 다음 폴링까지 대기. 제한시간이 남아 있으면 true(계속), 넘겼거나 인터럽트되면 false(중단). */
    private boolean sleepUntil(long deadline) {
        if (System.currentTimeMillis() >= deadline) {
            return false;
        }
        try {
            Thread.sleep(POLL_MS);
            return true;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private static List<String> nextSteps(String alertId) {
        return List.of(
                "GET /api/alerts — 방금 만들어진 알림이 목록 맨 위에 있다",
                "GET /api/alerts/" + alertId + "/lineage — 이 알림의 공격 경로 그래프",
                "GET /api/alerts/summary — 대시보드 집계에 반영된 모습",
                "POST /api/alerts/" + alertId + "/respond — responder 로 프로세스 종료 조치");
    }
}
