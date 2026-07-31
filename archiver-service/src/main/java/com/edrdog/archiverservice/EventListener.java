package com.edrdog.archiverservice;

import com.edrdog.archiverservice.clickhouse.ClickHouseWriter;
import com.edrdog.archiverservice.dto.Event;
import java.util.List;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

/**
 * events 토픽을 archiver 컨슈머 그룹으로 소비해 ClickHouse 에 적재하는 리스너.
 * detector 와 별도 그룹이라 같은 이벤트를 독립적으로 모두 받는다. 적재는 ClickHouseWriter 에 위임.
 *
 * 한 번의 poll 로 받은 배치를 통째로 넘긴다. 유입이 늘어 컨슈머 랙이 생길수록 배치가 커지므로
 * 정작 파트가 문제되는 고부하 구간에서 INSERT 횟수가 저절로 눌린다.
 * INSERT 실패 시 배치 전체가 재시도되어 일부 행이 중복될 수 있다. 조회용 원시 이벤트라 중복은 허용한다.
 */
@Component
public class EventListener {

    private final ClickHouseWriter writer;

    public EventListener(ClickHouseWriter writer) {
        this.writer = writer;
    }

    @KafkaListener(topics = "${edrdog.kafka.events-topic}", groupId = "${spring.kafka.consumer.group-id}")
    public void onEvents(List<Event> events) {
        writer.insert(events);
    }
}
