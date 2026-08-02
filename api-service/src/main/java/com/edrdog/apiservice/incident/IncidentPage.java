package com.edrdog.apiservice.incident;

import com.edrdog.apiservice.incident.web.IncidentResponse;

import java.util.List;

/**
 * 목록 한 페이지와 필터를 통과한 전체 건수. 본문은 배열이라 total 은 컨트롤러가 X-Total-Count 헤더로 싣는다.
 * total 이 null 이면 세지 않았다는 뜻이고, 그때는 헤더를 아예 붙이지 않는다.
 */
public record IncidentPage(List<IncidentResponse> incidents, Long total) {
}
