package com.edrdog.detectorservice.kafkastreams.serde;

import com.edrdog.detectorservice.kafkastreams.state.EventBufferState;
import com.edrdog.detectorservice.kafkastreams.topology.EventBuffer;
import com.google.protobuf.InvalidProtocolBufferException;
import org.apache.kafka.common.serialization.Deserializer;
import org.apache.kafka.common.serialization.Serde;
import org.apache.kafka.common.serialization.Serializer;

/**
 * 상태 저장소 값(EventBuffer) ↔ Protobuf 바이트.
 *
 * <p>{@link EventBuffer} 는 프로세서가 리스트를 제자리에서 깎는 가변 객체라 그대로 두고,
 * 저장할 때만 {@link EventBufferState} 로 옮긴다. 상태를 불변 메시지로 바꾸면 판정 루프가
 * 매번 버퍼 전체를 새로 만드는 코드가 된다.
 */
public class EventBufferSerde implements Serde<EventBuffer> {

    @Override
    public Serializer<EventBuffer> serializer() {
        return (topic, buffer) -> buffer == null ? null : toState(buffer).toByteArray();
    }

    @Override
    public Deserializer<EventBuffer> deserializer() {
        return (topic, bytes) -> {
            if (bytes == null) {
                return null;
            }
            try {
                return fromState(EventBufferState.parseFrom(bytes));
            } catch (InvalidProtocolBufferException e) {
                throw new IllegalArgumentException("EventBuffer 역직렬화 실패 (topic=" + topic + ")", e);
            }
        };
    }

    private static EventBufferState toState(EventBuffer buffer) {
        return EventBufferState.newBuilder()
                .addAllEvents(buffer.events)
                .addAllPending(buffer.pending)
                .setMaxTs(buffer.maxTs)
                .setLastUpdatedWallMs(buffer.lastUpdatedWallMs)
                .build();
    }

    private static EventBuffer fromState(EventBufferState state) {
        EventBuffer buffer = new EventBuffer();
        // 프로세서가 remove(0) 로 앞을 깎는다. proto 가 준 불변 리스트를 그대로 담으면 그 자리에서 터진다.
        buffer.events.addAll(state.getEventsList());
        buffer.pending.addAll(state.getPendingList());
        buffer.maxTs = state.getMaxTs();
        buffer.lastUpdatedWallMs = state.getLastUpdatedWallMs();
        return buffer;
    }
}
