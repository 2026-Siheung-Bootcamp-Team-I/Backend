package com.edrdog.detector.api;

import com.edrdog.detector.dto.Alert;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedDeque;

/**
 * alerts 토픽을 구독해 최근 판정 결과를 메모리에 보관한다 (조회 엔드포인트용).
 * detector 가 발행한 alert 를 그대로 되읽어 GET /api/alerts/recent 로 노출 = 발행→판정 결과 확인 루프.
 * responder 와는 별도 컨슈머 그룹이라 서로 간섭하지 않는다.
 */
@Component
public class RecentAlerts {

    private static final Logger log = LoggerFactory.getLogger(RecentAlerts.class);
    private static final int MAX = 50;

    private final ObjectMapper mapper = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    private final ConcurrentLinkedDeque<Alert> recent = new ConcurrentLinkedDeque<>();

    @KafkaListener(topics = "${edrdog.kafka.alerts-topic}", groupId = "detector-alerts-view")
    public void onAlert(String payload) {
        try {
            Alert alert = mapper.readValue(payload, Alert.class);
            recent.addFirst(alert);
            while (recent.size() > MAX) {
                recent.pollLast();
            }
        } catch (Exception e) {
            log.warn("alert 파싱 실패: {}", payload, e);
        }
    }

    /** 최신순 최근 alert 목록 (스냅샷). */
    public List<Alert> list() {
        return new ArrayList<>(recent);
    }
}
