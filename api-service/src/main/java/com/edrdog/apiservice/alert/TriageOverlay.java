package com.edrdog.apiservice.alert;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * 트리아지 status 오버레이 행(alert_status, incident_status)의 공통 계약과 병합 규칙.
 * 판정기록은 ClickHouse, status 는 MySQL 이라 DB 조인이 안 되므로 병합은 항상 앱에서 일어난다.
 * 그 병합 규칙은 하나뿐이다: <b>오버레이에 행이 없으면 open</b>.
 */
// alert 와 incident 가 이 규칙을 각자 구현하면 기본값이 갈릴 때 두 화면이 다른 답을 준다.
public interface TriageOverlay {

    String getId();

    String getStatus();

    /** id 목록의 오버레이 status. 트리아지 안 된 id 는 결과에 없다(읽을 때 {@link #statusOf(Map, String)} 로 open 이 된다). */
    static <T extends TriageOverlay> Map<String, String> load(JpaRepository<T, String> repo, List<String> ids) {
        if (ids.isEmpty()) {
            return Map.of();    // 빈 목록으로 findAllById 를 부르면 의미 없는 왕복이 생긴다
        }
        return repo.findAllById(ids).stream()
                .collect(Collectors.toMap(TriageOverlay::getId, TriageOverlay::getStatus));
    }

    /** 단건 status. 오버레이 행이 없으면 open 이다. */
    static <T extends TriageOverlay> String statusOf(JpaRepository<T, String> repo, String id) {
        return repo.findById(id).map(TriageOverlay::getStatus).orElse(AlertStatus.OPEN);
    }

    /** 이미 읽어 둔 오버레이에서 꺼낸다. 없으면 open 이다. */
    static String statusOf(Map<String, String> loaded, String id) {
        return loaded.getOrDefault(id, AlertStatus.OPEN);
    }
}
