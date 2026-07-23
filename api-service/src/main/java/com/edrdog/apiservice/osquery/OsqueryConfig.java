package com.edrdog.apiservice.osquery;

/**
 * 엔드포인트에 내려줄 osquery 수집 설정(osquery.conf 의 schedule). config 엔드포인트가 그대로 응답한다.
 *
 * <p>스케줄 쿼리 이름이 result-log 의 {@code name} 으로 찍히므로, collector 의 정규화 규칙과 맞춘다:
 * {@code socket_events}(이름에 socket 포함)는 network 로, {@code process_events}는 process 로 매핑된다.
 * 각 쿼리 컬럼(path/cmdline/parent, remote_address/remote_port)도 RawEventMapper 가 읽는 이름과 맞춘다.
 */
public final class OsqueryConfig {

    /** 프로세스 생성·소켓 연결 evented 테이블을 수집하는 최소 스케줄. */
    public static final String SCHEDULE_JSON = """
            {
              "options": {
                "host_identifier": "hostname",
                "schedule_splay_percent": 10,
                "disable_events": false,
                "events_expiry": 3600
              },
              "schedule": {
                "process_events": {
                  "query": "SELECT path, cmdline, parent, pid, time FROM process_events WHERE path != ''",
                  "interval": 10,
                  "description": "프로세스 생성 이벤트"
                },
                "socket_events": {
                  "query": "SELECT path, remote_address, remote_port, pid, time FROM socket_events WHERE action = 'connect' AND remote_address != ''",
                  "interval": 10,
                  "description": "아웃바운드 소켓 연결 이벤트"
                }
              }
            }
            """;

    private OsqueryConfig() {
    }
}
