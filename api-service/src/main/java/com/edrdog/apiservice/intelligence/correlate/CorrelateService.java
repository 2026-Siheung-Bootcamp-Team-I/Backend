package com.edrdog.apiservice.intelligence.correlate;

import com.edrdog.apiservice.clickhouse.ClickHouseReader;
import com.edrdog.apiservice.query.ClickHouseQuery;
import com.edrdog.apiservice.web.EventResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * 관측 조회 + 프로세스 보정 + 실시간 DNS 조회를 엮어 상관분석 응답을 만든다.
 *
 * <p>조립·매칭 자체는 전부 순수 클래스(CorrelationBuilder, DnsProcessBackfill)에 있고
 * 여기서는 그 순서와 바깥 세계(ClickHouse, DNS)와의 연결만 맡는다.
 */
@Service
public class CorrelateService {

    private final ClickHouseReader reader;
    private final CorrelateQueryBuilder builder;
    private final DnsResolver dns;
    private final ObjectMapper mapper;

    public CorrelateService(ClickHouseReader reader, CorrelateQueryBuilder builder, DnsResolver dns,
                            ObjectMapper mapper) {
        this.reader = reader;
        this.builder = builder;
        this.dns = dns;
        this.mapper = mapper;
    }

    public CorrelateResponse correlate(String tenantId, CorrelateTarget target, Long from, Long to,
                                       Integer limit, boolean liveDns) {
        List<EventResponse> seed = read(builder.seedEvents(tenantId, target, from, to, limit));
        List<CorrelatedEvent> events = DnsProcessBackfill.apply(seed, backfillCandidates(tenantId, seed));

        DnsLookupResponse live = liveDns ? lookup(target) : null;
        CorrelationGraph graph = CorrelationBuilder.build(target, events,
                live == null ? null : live.forward(), live == null ? null : live.reverse());

        return new CorrelateResponse(target, seed.size(), graph.nodes(), graph.edges(), live);
    }

    /** 도메인이면 정방향만, IP 면 역방향만 묻는다. 반대 방향은 물어볼 것이 없다. */
    public DnsLookupResponse lookup(CorrelateTarget target) {
        if (target.kind() == TargetKind.DOMAIN) {
            return new DnsLookupResponse(target, dns.forward(target.value()), null);
        }
        return new DnsLookupResponse(target, null, dns.reverse(target.value()));
    }

    /**
     * 프로세스가 빈 DNS 이벤트가 있을 때만 보정 후보를 조회한다.
     * 보정할 것이 없으면 질의를 아예 보내지 않는다(Windows 만 있는 조직은 이 경로를 안 탄다).
     */
    private List<EventResponse> backfillCandidates(String tenantId, List<EventResponse> seed) {
        Optional<long[]> window = DnsProcessBackfill.candidateWindow(seed);
        List<String> ips = DnsProcessBackfill.answerIpsNeedingBackfill(seed);
        if (window.isEmpty() || ips.isEmpty()) {
            return List.of();
        }
        return read(builder.destinationEvents(tenantId, ips, window.get()[0], window.get()[1]));
    }

    private List<EventResponse> read(ClickHouseQuery query) {
        List<Map<String, Object>> rows = reader.query(query);
        return rows.stream().map(row -> EventResponse.fromRow(row, mapper)).toList();
    }
}
