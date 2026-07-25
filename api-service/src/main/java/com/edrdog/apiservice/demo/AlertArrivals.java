package com.edrdog.apiservice.demo;

import com.edrdog.apiservice.alert.AlertId;
import com.edrdog.apiservice.alert.dto.Alert;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * alerts 토픽에 판정 결과가 <b>도착한 시각</b>을 alert id 별로 기록한다 (데모 타임라인 계측용).
 *
 * <p>적재용 리스너(AlertIngestListener)와 별도 컨슈머 그룹이라 서로 간섭하지 않는다. 굳이 분리한 이유는
 * 발표에서 보여줄 구간이 "Kafka → Streams → Kafka" 이기 때문이다. detector 가 판정을 alerts 토픽에
 * 되돌려준 시점과, 그게 ClickHouse 에 적재돼 조회 가능해진 시점을 따로 찍어야 두 단계를 구분해 보여줄 수 있다.
 *
 * <p>id 계산은 적재 경로와 같은 {@link AlertId} 를 쓴다. 그래서 호출자는 발행 전에 기대 id 를 미리 계산해
 * 이번 회차 alert 만 정확히 기다릴 수 있다(과거 회차의 같은 룰 alert 에 속지 않는다).
 */
@Component
public class AlertArrivals {

    /** 보관 상한. 발표용 계측이라 최근 것만 있으면 된다. */
    private static final int MAX = 200;

    private final Map<String, Long> arrivedAt = Collections.synchronizedMap(
            new LinkedHashMap<>(16, 0.75f, false) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, Long> eldest) {
                    return size() > MAX;
                }
            });

    @KafkaListener(topics = "${edrdog.kafka.alerts-topic}", groupId = "api-demo-arrivals")
    public void onAlert(Alert alert) {
        if (alert == null || alert.tenantId() == null || alert.host() == null || alert.ruleId() == null) {
            return;
        }
        String id = AlertId.of(alert.tenantId(), alert.host(), alert.ruleId(), alert.ts());
        arrivedAt.putIfAbsent(id, System.currentTimeMillis());
    }

    /** 그 alert 가 alerts 토픽에서 관측된 시각(epoch millis). 아직 안 왔으면 empty. */
    public Optional<Long> arrivedAt(String alertId) {
        return Optional.ofNullable(arrivedAt.get(alertId));
    }
}
