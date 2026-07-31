package com.edrdog.apiservice.web;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;

/**
 * 이벤트의 결정적 id 생성(순수). 이벤트 자체의 값을 UUID v3(name-based)로 접어 만든다(AlertId 와 같은 방식).
 *
 * <p><b>id 컬럼을 만들지 않은 이유.</b> edrdog.events 에는 id 가 없다. 컬럼을 늘리려면 archiver
 * 적재 경로와 스키마 마이그레이션까지 같이 움직여야 하는데, 이미 있는 컬럼으로 접으면 그 비용이 전부 없다.
 *
 * <p><b>씨앗은 host|ts|type|process|pid|parent|dest_ip|dest_port 다.</b> 조회 경로마다 뽑는 컬럼이
 * 달라서, 모든 경로에 있는 것만 남긴 결과다. EventQueryBuilder.events() 는 전체 컬럼을 뽑지만
 * lineageEvents() 는 type/ts/process/parent/dest_ip/dest_port/detail 만 뽑는다. 그래서
 * <ul>
 *   <li>host — 어느 행에 있는지가 경로마다 다르지만(lineageEvents 는 SELECT 하지 않는다) 호출부는
 *       언제나 host 를 쥐고 있다. lineageEvents 는 host 를 인자로 받아 WHERE 를 걸고, 사건 타임라인은
 *       응답 최상위에 host 가 있다. 그래서 행에서 읽지 않고 <b>인자로 필수</b>로 받는다. 새 조회 경로가
 *       host 를 빠뜨리면 조용히 다른 id 가 나오는 대신 컴파일이 깨진다.</li>
 *   <li>cmdline, domain, sha256 — events() 에만 있고 호출부도 따로 쥐고 있지 않다. 넣으면 같은 이벤트가
 *       계보 경로에서 다른 id 를 받아 화면이 "알림의 원본 이벤트" 와 "타임라인의 그 줄" 을 다르게 본다. 탈락.</li>
 *   <li>detail 원문 — 두 조회 경로엔 다 있지만 타임라인 줄(IncidentTimelineResponse.Entry)이 원문을
 *       버리고 pid 만 들고 있다. 대신 그 pid 를 씨앗에 쓴다. 동명 프로세스를 가르는 힘은 pid 가 낸다.</li>
 *   <li>ingested_at — 재적재하면 바뀐다. id 가 흔들린다. 탈락.</li>
 *   <li>tenant_id — 어느 경로에서도 SELECT 하지 않고 호출부가 행 단위로 들고 있지도 않다. 대신 모든
 *       조회가 WHERE 에 tenant 를 강제하므로 id 는 언제나 한 조직의 결과 안에서만 해석된다.</li>
 * </ul>
 *
 * <p><b>충돌.</b> 같은 호스트가 같은 밀리초에 같은 pid 로 같은 type/부모/목적지의 이벤트를 두 건 냈을
 * 때만 같은 id 가 된다. 그 둘은 화면에 그려지는 값이 전부 같아 사용자도 구분할 수단이 없으니, id 를
 * 나눠 봐야 가리키는 대상이 갈리지 않는다. host 가 씨앗에 있으므로 서로 다른 기기의 이벤트가 같은 id 로
 * 보이는 일은 없다. 동일 이미지를 대량 배포한 환경처럼 여러 기기가 같은 이벤트를 같은 시각에 내는 곳은
 * EDR 이 흔히 놓이는 환경이고, 거기서 기기가 섞이면 조사하는 사람이 다른 기기를 같은 것으로 읽는다.
 */
public final class EventId {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private EventId() {
    }

    public static String of(String host, long ts, String type, String process, Integer pid,
                            String parent, String destIp, Integer destPort) {
        // dest_port 는 events 조회가 0, 타임라인이 null 로 "없음" 을 표현한다. 같은 것으로 접는다.
        String seed = text(host) + "|" + ts + "|" + text(type) + "|" + text(process)
                + "|" + (pid == null ? "" : pid) + "|" + text(parent) + "|" + text(destIp)
                + "|" + (destPort == null ? 0 : destPort);
        return UUID.nameUUIDFromBytes(seed.getBytes(StandardCharsets.UTF_8)).toString();
    }

    /**
     * ClickHouse events 행에서 바로 만든다. pid 는 detail(JSON) 안에 있어 여기서 꺼낸다.
     * host 는 행에 없는 경로가 있어 인자로 받는다.
     */
    public static String ofRow(String host, Map<String, Object> row) {
        EventDetail detail = EventDetail.parse(text(row.get("detail")), MAPPER);
        return of(host, asLong(row.get("ts")), text(row.get("type")), text(row.get("process")), detail.pid(),
                text(row.get("parent")), text(row.get("dest_ip")), asInt(row.get("dest_port")));
    }

    private static String text(Object v) {
        return v == null ? "" : String.valueOf(v);
    }

    /** ClickHouse UInt64 는 JSON 에서 문자열로 온다(EventResponse.asLong 과 같은 이유). */
    private static long asLong(Object v) {
        if (v == null) {
            return 0L;
        }
        if (v instanceof Number n) {
            return n.longValue();
        }
        return Long.parseLong(String.valueOf(v));
    }

    private static Integer asInt(Object v) {
        if (v == null) {
            return null;
        }
        if (v instanceof Number n) {
            return n.intValue();
        }
        return Integer.parseInt(String.valueOf(v));
    }
}
