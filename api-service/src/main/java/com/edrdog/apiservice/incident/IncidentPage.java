package com.edrdog.apiservice.incident;

import com.edrdog.apiservice.incident.web.IncidentResponse;

import java.util.List;

/**
 * 목록 한 페이지와 필터를 통과한 전체 건수.
 *
 * <p>total 을 응답 본문에 담지 않고 이렇게 따로 들고 나가는 이유는 목록 응답이 배열이기 때문이다.
 * 컨트롤러가 X-Total-Count 헤더로 실어 보낸다(알림·이벤트 목록과 같은 이름).
 *
 * <p>total 이 null 이면 세지 않았다는 뜻이고, 그때는 헤더를 아예 붙이지 않는다
 * (AlertService.AlertPage 와 같은 규약이라 PageHeaders 에 그대로 넘길 수 있다).
 */
public record IncidentPage(List<IncidentResponse> incidents, Long total) {
}
