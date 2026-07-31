package com.edrdog.apiservice.intelligence.correlate;

import com.edrdog.apiservice.web.EventResponse;

import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * 프로세스가 빈 DNS 이벤트에 "진짜 질의한 프로세스"를 되짚어 붙인다.
 *
 * <p>왜 필요한가: macOS 는 DNS 질의가 전부 mDNSResponder 를 거쳐 나가서 소켓 주인을 찾으면
 * 언제나 mDNSResponder 가 나온다. 에이전트는 틀린 값을 채우느니 비워 두는 쪽을 골랐고
 * (l7.go 의 dnsEvent 주석), Windows(ETW)는 프로세스가 정상적으로 채워진다. 그래서 같은 화면이
 * OS 에 따라 다르게 보인다. 서버에서 양쪽을 같게 만든다.
 *
 * <p>어떻게: 그 DNS 응답이 준 IP 로 직후에 실제로 붙은 network/l7 이벤트를 같은 호스트에서
 * 찾는다. 그 이벤트의 프로세스가 질의한 장본인이다.
 *
 * <p>결과는 관측이 아니라 추론이다. CorrelatedEvent 의 별도 칸에 담아 응답에서 구분되게 한다.
 * 못 찾으면 비워 둔다. 에이전트가 지킨 원칙을 서버가 무너뜨리지 않는다.
 */
public final class DnsProcessBackfill {

    /**
     * DNS 응답 뒤 이 시간 안의 접속만 그 질의 때문이라고 본다.
     *
     * <p>더 늘리면 캐시된 IP 로 한참 뒤에 붙은 접속까지 질의자로 둔갑한다. TTL 이 짧은 도메인이
     * 흔해 30초면 앱이 응답을 받고 붙기까지는 충분히 덮는다.
     */
    static final long WINDOW_MS = 30_000;

    /**
     * 접속이 질의보다 살짝 앞서 찍혀도 허용하는 폭.
     *
     * <p>같은 에이전트가 찍은 두 이벤트라 시계는 같지만, 센서가 다르면 밀리초 단위로 순서가
     * 뒤집혀 올라올 수 있다. 그걸 못 잇는 편이 더 손해다.
     */
    static final long TOLERANCE_MS = 1_000;

    private static final String TYPE_DNS = "dns";
    private static final Set<String> CONNECT_TYPES = Set.of("network", "l7");

    private DnsProcessBackfill() {
    }

    /** 이벤트 목록을 그대로 유지한 채, 보정할 수 있는 DNS 이벤트에만 추론 프로세스를 덧붙인다. */
    public static List<CorrelatedEvent> apply(List<EventResponse> events, List<EventResponse> candidates) {
        return events.stream().map(e -> correlate(e, candidates)).toList();
    }

    /** 보정이 필요한(프로세스가 비었고 응답 IP 가 있는) DNS 이벤트의 응답 IP 를 모은다. 후보 조회 범위가 된다. */
    public static List<String> answerIpsNeedingBackfill(List<EventResponse> events) {
        return events.stream()
                .filter(DnsProcessBackfill::needsBackfill)
                .flatMap(e -> e.dnsAnswers().stream())
                .distinct()
                .toList();
    }

    private static CorrelatedEvent correlate(EventResponse e, List<EventResponse> candidates) {
        if (!needsBackfill(e)) {
            return CorrelatedEvent.observed(e);
        }
        Set<String> answers = Set.copyOf(e.dnsAnswers());
        return candidates.stream()
                .filter(c -> matches(e, c, answers))
                // 질의에 가장 가까운 접속이 그 질의로 시작된 접속일 가능성이 가장 높다.
                .min(Comparator.comparingLong(c -> Math.abs(c.ts() - e.ts())))
                .map(c -> new CorrelatedEvent(e, c.process(), basis(c)))
                .orElseGet(() -> CorrelatedEvent.observed(e));
    }

    private static boolean needsBackfill(EventResponse e) {
        return TYPE_DNS.equals(e.type())
                && isBlank(e.process())
                && e.dnsAnswers() != null
                && !e.dnsAnswers().isEmpty();
    }

    private static boolean matches(EventResponse dns, EventResponse candidate, Set<String> answers) {
        return CONNECT_TYPES.contains(candidate.type())
                && !isBlank(candidate.process())
                && dns.host().equals(candidate.host())
                && answers.contains(candidate.destIp())
                && candidate.ts() >= dns.ts() - TOLERANCE_MS
                && candidate.ts() <= dns.ts() + WINDOW_MS;
    }

    /** 추론의 근거. 조사하는 사람이 이 값을 보고 스스로 되짚어 볼 수 있어야 한다. */
    private static String basis(EventResponse c) {
        return c.type() + " 이벤트 dest_ip=" + c.destIp() + " ts=" + c.ts();
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    /** 보정 후보를 찾을 시간 범위. 대상 DNS 이벤트 전부를 덮는 한 번의 조회로 끝내려고 쓴다. */
    public static Optional<long[]> candidateWindow(List<EventResponse> events) {
        List<EventResponse> targets = events.stream().filter(DnsProcessBackfill::needsBackfill).toList();
        if (targets.isEmpty()) {
            return Optional.empty();
        }
        long from = targets.stream().mapToLong(EventResponse::ts).min().getAsLong() - TOLERANCE_MS;
        long to = targets.stream().mapToLong(EventResponse::ts).max().getAsLong() + WINDOW_MS;
        return Optional.of(new long[]{from, to});
    }
}
