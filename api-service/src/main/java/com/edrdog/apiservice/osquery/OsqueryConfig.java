package com.edrdog.apiservice.osquery;

/**
 * 엔드포인트에 내려줄 osquery 수집 설정(osquery.conf 의 schedule). config 엔드포인트가 그대로 응답한다.
 *
 * <p>스케줄 쿼리 이름이 result-log 의 {@code name} 으로 찍히므로, collector 의 정규화 규칙과 맞춘다:
 * {@code socket_events}(이름에 socket 포함)는 network 로, {@code process_events}/{@code process_etw_events}는
 * process 로 매핑된다. 각 쿼리 컬럼(path/cmdline/parent, remote_address/remote_port)도 RawEventMapper 가
 * 읽는 이름과 맞춘다.
 *
 * <p>플랫폼별로 감시 테이블이 다르므로 enroll 시 받은 platform 으로 스케줄을 갈라 내려준다.
 * <ul>
 *   <li>macOS: {@code es_process_events}(EndpointSecurity) + {@code socket_events}</li>
 *   <li>Windows: {@code process_etw_events}(ETW). 실시간 소켓 테이블이 없어 network 는 Zeek 담당.</li>
 * </ul>
 * parent 는 두 테이블 모두 PID 라, {@code processes} 조인으로 이름을 채워 collector 가 그대로 쓰게 한다.
 */
public final class OsqueryConfig {

    /**
     * macOS: EndpointSecurity 프로세스 생성 + 아웃바운드 소켓. parent(ppid)는 processes 조인으로 이름화.
     * 스케줄 키는 process_events/socket_events 로 둬 RawEventMapper 의 type 판정(socket→network)과 맞춘다.
     */
    private static final String MACOS_JSON = """
            {
              "options": {
                "host_identifier": "hostname",
                "schedule_splay_percent": 10,
                "disable_events": false,
                "events_expiry": 3600
              },
              "schedule": {
                "process_events": {
                  "query": "SELECT e.path AS path, e.cmdline AS cmdline, p.name AS parent, e.pid AS pid, e.time AS time FROM es_process_events e LEFT JOIN processes p ON e.parent = p.pid WHERE e.event_type = 'exec'",
                  "interval": 10,
                  "description": "프로세스 생성 이벤트(EndpointSecurity)"
                },
                "socket_events": {
                  "query": "SELECT path, remote_address, remote_port, pid, time FROM socket_events WHERE action = 'connect' AND remote_address != '' AND remote_address NOT IN ('127.0.0.1', '::1', '0.0.0.0')",
                  "interval": 10,
                  "description": "아웃바운드 소켓 연결 이벤트"
                }
              }
            }
            """;

    /**
     * Windows: ETW 프로세스 생성. parent(ppid)는 processes 조인으로 이름화.
     * network 는 core osquery 실시간 소켓 테이블이 없어 여기서 다루지 않는다(Zeek 담당).
     */
    private static final String WINDOWS_JSON = """
            {
              "options": {
                "host_identifier": "hostname",
                "schedule_splay_percent": 10,
                "disable_events": false,
                "events_expiry": 3600
              },
              "schedule": {
                "process_etw_events": {
                  "query": "SELECT e.path AS path, e.cmdline AS cmdline, p.name AS parent, e.pid AS pid, e.time AS time FROM process_etw_events e LEFT JOIN processes p ON e.ppid = p.pid WHERE e.type = 'ProcessStart'",
                  "interval": 10,
                  "description": "프로세스 생성 이벤트(ETW)"
                }
              }
            }
            """;

    /**
     * enroll 시 저장한 platform 으로 스케줄을 고른다. 값에 windows 가 들어가면 Windows, 그 외(darwin/미상)는 macOS.
     * osquery {@code platform_type} 은 버전에 따라 문자열이 다를 수 있어 느슨하게 판정한다.
     * ("darwin" 이 "win" 을 부분문자열로 포함하므로 "windows" 로 정확히 본다.)
     */
    public static String forPlatform(String platform) {
        return isWindows(platform) ? WINDOWS_JSON : MACOS_JSON;
    }

    private static boolean isWindows(String platform) {
        return platform != null && platform.toLowerCase().contains("windows");
    }

    private OsqueryConfig() {
    }
}
