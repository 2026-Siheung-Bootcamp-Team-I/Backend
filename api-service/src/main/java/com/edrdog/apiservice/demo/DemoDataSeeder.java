package com.edrdog.apiservice.demo;

import com.edrdog.apiservice.alert.AlertService;
import com.edrdog.apiservice.alert.dto.Alert;
import com.edrdog.apiservice.clickhouse.ClickHouseReader;
import com.edrdog.apiservice.query.ClickHouseQuery;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

/**
 * 발표용 과거 데이터를 부팅 시 채운다. {@code edrdog.demo.seed=true} 일 때만 빈으로 올라온다.
 *
 * <p>events(ClickHouse)와 alerts(MySQL)를 저장소에 직접 넣는다. Kafka 를 거치지 않는 이유는
 * 과거 시각으로 발행하면 detector 의 event-time 윈도우가 성립하지 않아 판정이 안 나오기 때문이다.
 * 실시간 시연은 detector 의 시나리오 발행 API 로 하고, 여기서는 배경만 만든다.
 *
 * <p>재적재 기준이 둘로 나뉜다. events 는 ClickHouse 가 emptyDir 라 파드 재시작으로 사라질 수 있어
 * "비어 있으면 다시" 채우고, alerts 는 AlertService 가 결정적 id 로 멱등 적재하므로 매번 호출해도 안전하다.
 *
 * <p>시드 실패로 앱이 못 뜨면 발표 자체가 막히므로, 예외는 삼키고 경고만 남긴다.
 */
@Component
@ConditionalOnProperty(name = "edrdog.demo.seed", havingValue = "true")
public class DemoDataSeeder {

    private static final Logger log = LoggerFactory.getLogger(DemoDataSeeder.class);

    private static final String TENANT_ID = String.valueOf(DemoAccountSeeder.TENANT_ID);

    private final DemoEventWriter writer;
    private final ClickHouseReader reader;
    private final AlertService alerts;
    private final String table;

    public DemoDataSeeder(DemoEventWriter writer, ClickHouseReader reader, AlertService alerts,
                          @Value("${edrdog.clickhouse.table}") String table) {
        this.writer = writer;
        this.reader = reader;
        this.alerts = alerts;
        this.table = table;
    }

    /** 데모 tenant 가 확보된 뒤에만 호출해야 한다(DemoSeeder 가 순서를 지킨다). */
    public void seed() {
        long now = System.currentTimeMillis();
        seedEvents(now);
        seedAlerts(now);
    }

    /**
     * 데모 events 가 없을 때만 채운다. ClickHouse 는 dedup 이 없어 두 번 넣으면 그대로 두 배가 된다.
     * 판별은 대표 호스트({@link DemoData#MARKER_HOST}) 유무로 한다. 같은 tenant 에 개발 중 남은
     * 다른 이벤트가 있어도 데모 데이터는 정상적으로 채워져야 하기 때문이다.
     */
    private void seedEvents(long now) {
        try {
            if (alreadySeeded()) {
                log.info("데모 events 가 이미 있어 건너뜁니다 (tenantId={}, host={})",
                        TENANT_ID, DemoData.MARKER_HOST);
                return;
            }
            List<DemoEvent> events = DemoData.events(TENANT_ID, now);
            writer.insert(events);
            log.info("데모 events 적재: {}건 (최근 {}일, tenantId={})", events.size(), DemoData.DAYS, TENANT_ID);
        } catch (Exception e) {
            log.warn("데모 events 적재 실패. ClickHouse 상태를 확인하세요. 앱은 계속 뜹니다.", e);
        }
    }

    /** 대표 호스트의 events 가 이미 있는지. */
    private boolean alreadySeeded() {
        ClickHouseQuery q = new ClickHouseQuery(
                "SELECT count() AS cnt FROM " + table
                        + " WHERE tenant_id = {tenantId:String} AND host = {host:String}",
                Map.of("tenantId", TENANT_ID, "host", DemoData.MARKER_HOST));
        List<Map<String, Object>> rows = reader.query(q);
        return !rows.isEmpty() && Long.parseLong(String.valueOf(rows.get(0).get("cnt"))) > 0;
    }

    /** alerts 는 멱등 적재라 매번 호출해도 한 행만 남는다(트리아지한 status 도 보존된다). */
    private void seedAlerts(long now) {
        try {
            List<Alert> demoAlerts = DemoData.alerts(TENANT_ID, now);
            demoAlerts.forEach(alerts::ingest);
            log.info("데모 alerts 적재: {}건 (tenantId={})", demoAlerts.size(), TENANT_ID);
        } catch (Exception e) {
            log.warn("데모 alerts 적재 실패. 앱은 계속 뜹니다.", e);
        }
    }
}
