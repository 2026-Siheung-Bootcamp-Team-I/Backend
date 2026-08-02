package com.edrdog.apiservice.search;

import com.edrdog.apiservice.alert.ThreatCatalog;
import com.edrdog.apiservice.clickhouse.ClickHouseReader;
import com.edrdog.apiservice.host.HostService;
import com.edrdog.apiservice.host.web.HostResponse;
import com.edrdog.apiservice.search.web.AlertHit;
import com.edrdog.apiservice.search.web.EventHit;
import com.edrdog.apiservice.search.web.SearchResponse;
import com.edrdog.apiservice.search.web.SearchSection;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

/**
 * 상단바 통합 검색. 알림(ClickHouse)·호스트(HostService)·이벤트(ClickHouse)를 한 번에 훑어
 * 종류별 상위 N건씩 돌려준다. 모든 조회는 tenant 로 격리한다.
 */
@Service
public class SearchService {

    private final ClickHouseReader reader;
    private final SearchQueryBuilder builder;
    private final HostService hosts;

    public SearchService(ClickHouseReader reader, SearchQueryBuilder builder, HostService hosts) {
        this.reader = reader;
        this.builder = builder;
        this.hosts = hosts;
    }

    /** term 은 이미 정규화된 질의어여야 한다(SearchTerm.normalize). 길이 검증은 400 으로 돌려줘야 해서 웹 계층이 먼저 한다. */
    public SearchResponse search(String tenantId, String term, long from, long to, Integer limit) {
        int size = SearchQueryBuilder.pageSize(limit);
        return new SearchResponse(term, from, to,
                SearchSection.of(matchingHosts(tenantId, term), size),
                SearchSection.of(alertHits(tenantId, term, from, to, limit), size),
                SearchSection.of(eventHits(tenantId, term, from, to, limit), size));
    }

    /**
     * 이름이 걸린 엔드포인트. 부분일치를 SQL 로 내리려면 목록·위험도 집계 경로를 하나 더 만들어야 해서
     * 통째로 받아 메모리에서 거른다(tenant 당 수십 대 규모).
     * 여기만 시간 범위를 안 건다. 조용히 있던 기기가 기간 밖이라고 빠지면 검색이 틀린 답을 준다.
     */
    private List<HostResponse> matchingHosts(String tenantId, String term) {
        return hosts.hosts(tenantId).stream()
                .filter(host -> SearchTerm.matches(host.host(), term))
                .toList();
    }

    private List<AlertHit> alertHits(String tenantId, String term, long from, long to, Integer limit) {
        List<Map<String, Object>> rows = reader.query(
                builder.alerts(tenantId, term, threatRuleIds(term), from, to, limit));
        return rows.stream().map(AlertHit::fromRow).toList();
    }

    private List<EventHit> eventHits(String tenantId, String term, long from, long to, Integer limit) {
        List<Map<String, Object>> rows = reader.query(builder.events(tenantId, term, from, to, limit));
        return rows.stream().map(EventHit::fromRow).toList();
    }

    /**
     * 한글 위협명이 걸리는 ruleId 들(순수). ClickHouse 에는 영문 ruleId 만 적재되므로 화면에서 본 대로 친 말이
     * 조회에 닿으려면 여기서 옮겨야 한다. 카탈로그는 룰 몇 개짜리 상수 맵이라 매번 훑어도 비용이 없다.
     */
    public static List<String> threatRuleIds(String term) {
        return ThreatCatalog.all().stream()
                .filter(entry -> SearchTerm.matches(entry.threatName(), term))
                .map(ThreatCatalog.Entry::ruleId)
                .toList();
    }
}
