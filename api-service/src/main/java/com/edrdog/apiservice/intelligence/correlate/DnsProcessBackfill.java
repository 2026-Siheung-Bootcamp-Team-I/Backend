package com.edrdog.apiservice.intelligence.correlate;

import com.edrdog.apiservice.event.EventResponse;

import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * 프로세스가 빈 DNS 이벤트(macOS 는 질의가 mDNSResponder 를 거쳐 나가 에이전트가 비워 보낸다)에,
 * 그 응답 IP 로 직후에 같은 호스트에서 붙은 network/l7 이벤트의 프로세스를 되짚어 붙인다(순수).
 * 결과는 관측이 아니라 추론이라 CorrelatedEvent 의 별도 칸에 담고, 못 찾으면 비워 둔다.
 */
public final class DnsProcessBackfill {

    /** DNS 응답 뒤 이 시간 안의 접속만 그 질의 때문이라고 본다. 늘리면 캐시된 IP 로 한참 뒤에 붙은 접속까지 질의자로 둔갑한다. */
    static final long WINDOW_MS = 30_000;

    /** 접속이 질의보다 살짝 앞서 찍혀도 허용하는 폭. 센서가 다르면 밀리초 단위로 순서가 뒤집혀 올라온다. */
    static final long TOLERANCE_MS = 1_000;

    private static final String TYPE_DNS = "dns";
    private static final Set<String> CONNECT_TYPES = Set.of("network", "l7");

    private DnsProcessBackfill() {
    }

    /** 적재된 이벤트는 그대로 두고 조회 때만 덧붙인다. 이벤트 안에 채우면 관측값과 추측이 같은 자리에 앉는다. */
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
