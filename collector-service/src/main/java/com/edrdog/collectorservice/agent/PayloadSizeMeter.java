package com.edrdog.collectorservice.agent;

import com.edrdog.schema.Event;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 측정용 임시 코드. Protobuf 전환이 전송량을 얼마나 줄였는지 재려고 잠깐 둔다.
 *
 * <p>발행되는 것은 Protobuf 하나뿐이고, JSON 쪽은 <b>같은 이벤트를 직렬화만 해 본 값</b>이다.
 * 나가지 않는 바이트를 재는 것이라 그만큼 CPU 를 버린다. 그래서 기본값은 꺼짐이고,
 * 부하 테스트를 돌리는 동안에만 켠다. 수치를 확정하면 이 파일과 짝인 대시보드를 같이 걷어낸다.
 *
 * <p>대시보드: scripts/loadtest/dashboard-payload.json
 */
@Component
public class PayloadSizeMeter {

    private static final Logger log = LoggerFactory.getLogger(PayloadSizeMeter.class);

    /** 이름을 event.payload 로 두면 baseUnit 이 붙어 event_payload_bytes 로 나간다(기존 지표 규칙과 같다). */
    private static final String METER = "event.payload";

    private final MeterRegistry registry;
    private final boolean enabled;
    private final ObjectMapper mapper = new ObjectMapper();

    public PayloadSizeMeter(MeterRegistry registry,
                            @Value("${edrdog.metrics.compare-json:false}") boolean enabled) {
        this.registry = registry;
        this.enabled = enabled;
        if (enabled) {
            log.warn("페이로드 크기 비교 측정이 켜져 있다. 이벤트마다 JSON 직렬화를 한 번 더 한다 (측정용 임시 기능)");
        }
    }

    /** 발행 직전 호출. 실제 나가는 바이트와, 같은 이벤트를 JSON 으로 했을 때의 바이트를 같이 남긴다. */
    public void record(Event event, byte[] published) {
        if (!enabled) {
            return;
        }
        String type = event.getType();
        summary("protobuf", type).record(published.length);
        try {
            summary("json", type).record(asLegacyJson(event).length);
        } catch (Exception e) {
            log.debug("JSON 환산 실패 (측정만 건너뛴다)", e);
        }
    }

    /**
     * 전환 전 collector 가 실제로 보내던 형태를 그대로 되살린다.
     *
     * <p>그때는 12개 필드짜리 record 를 Jackson 이 통째로 직렬화했다. 안 채운 필드도 {@code null} 로
     * 실려 나갔고, 그 바이트가 이번에 없어진 것의 일부다. proto 의 JSON 매핑을 쓰면 빈 필드가 빠져
     * 실제보다 작게 잡히므로 여기서 손으로 맞춘다. 필드 순서도 그때 record 선언 순서다.
     */
    private byte[] asLegacyJson(Event e) throws Exception {
        Map<String, Object> old = new LinkedHashMap<>();
        old.put("host", e.getHost());
        old.put("type", e.getType());
        old.put("ts", e.getTs());
        old.put("process", orNull(e.getProcess()));
        old.put("parent", orNull(e.getParent()));
        old.put("cmdline", orNull(e.getCmdline()));
        old.put("destIp", orNull(e.getDestIp()));
        old.put("destPort", e.getDestPort());
        old.put("domain", orNull(e.getDomain()));
        old.put("detail", orNull(e.getDetail()));
        old.put("sha256", orNull(e.getSha256()));
        old.put("tenantId", orNull(e.getTenantId()));
        return mapper.writeValueAsBytes(old);
    }

    /** proto3 는 관측 못 한 값을 빈 문자열로 준다. 예전 record 는 그 자리에 null 을 담았다. */
    private static String orNull(String value) {
        return value.isEmpty() ? null : value;
    }

    /** micrometer 는 이름+태그가 같으면 같은 미터를 돌려준다. 매번 만들어도 새로 생기지 않는다. */
    private DistributionSummary summary(String format, String type) {
        return DistributionSummary.builder(METER)
                .description("events 로 나가는 이벤트 한 건의 크기. format=json 은 실제로 나가지 않는 환산값이다")
                .baseUnit("bytes")
                .tag("format", format)
                .tag("type", type)
                .publishPercentiles(0.5, 0.95, 0.99)
                .register(registry);
    }
}
