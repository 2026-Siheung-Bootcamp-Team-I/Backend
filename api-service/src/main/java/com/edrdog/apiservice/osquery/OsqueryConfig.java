package com.edrdog.apiservice.osquery;

/**
 * 엔드포인트에 내려줄 osquery 수집 설정(osquery.conf 의 schedule). config 엔드포인트가 그대로 응답한다.
 *
 * <p>스케줄 쿼리 이름이 result-log 의 {@code name} 으로 찍히므로, collector 의 정규화 규칙과 맞춘다:
 * 이름에 socket→network, file→file, script→script, 그 외→process 로 매핑된다.
 * ({@code process_events}/{@code process_etw_events}는 process, {@code script_events}/{@code script_etw_events}는 script,
 * {@code file_events}는 file.) 각 쿼리 컬럼(path/cmdline/parent, remote_address/remote_port, target_path)도
 * RawEventMapper 가 읽는 이름과 맞춘다. file/script 이벤트의 경로는 detector 가 MEDIUM 룰(T1059/T1547) 판정에 쓴다.
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
              "file_paths": {
                "autorun": [
                  "/Users/%/Library/LaunchAgents/%%",
                  "/Library/LaunchAgents/%%",
                  "/Library/LaunchDaemons/%%"
                ]
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
                },
                "script_events": {
                  "query": "SELECT e.path AS path, e.cmdline AS cmdline, p.name AS parent, e.pid AS pid, e.time AS time FROM es_process_events e LEFT JOIN processes p ON e.parent = p.pid WHERE e.event_type = 'exec' AND (e.path LIKE '%/bash' OR e.path LIKE '%/sh' OR e.path LIKE '%/zsh' OR e.path LIKE '%/python%' OR e.path LIKE '%/osascript')",
                  "interval": 10,
                  "description": "스크립트 인터프리터 실행. cmdline 의 스크립트 경로로 임시/다운로드 실행을 detector 가 MEDIUM(T1059) 판정"
                },
                "file_events": {
                  "query": "SELECT target_path, action, time FROM file_events WHERE action IN ('CREATED', 'UPDATED', 'MOVED_TO')",
                  "interval": 10,
                  "description": "자동실행(LaunchAgents/Daemons) 경로 FIM. target_path 로 지속성 확보를 detector 가 MEDIUM(T1547) 판정. file_paths.autorun 참조"
                }
              }
            }
            """;

    /**
     * Windows: ETW 프로세스 이벤트. parent(ppid)는 processes 조인으로 이름화.
     * network 는 core osquery 실시간 소켓 테이블이 없어 여기서 다루지 않는다(Zeek 담당).
     *
     * <p><b>ProcessStart 가 아니라 ProcessStop 을 받는다.</b> 실기기(osquery 5.23.1, Windows)에서
     * 커널 ETW 세션과 프로바이더가 모두 정상인데도 {@code process_etw_events} 에는 ProcessStop 만
     * 올라온다. 조건 없이 {@code SELECT type, path} 로 확인했을 때 ProcessStart 는 한 건도 없었다.
     * 그 상태로 ProcessStart 를 거르면 osquery 는 오류를 내지 않고 결과만 비워서, Windows 수집이
     * 통째로 조용히 0건이 된다.
     *
     * <p>종료 이벤트에도 path/cmdline 이 실려 있어 무엇이 실행됐는지는 그대로 알 수 있다. 다만
     * 프로세스가 끝나야 기록되므로 상주 프로세스는 잡지 못하고, 탐지가 사후에만 이뤄진다.
     * 스크립트처럼 짧게 끝나는 실행은 오히려 잘 잡힌다.
     */
    private static final String WINDOWS_JSON = """
            {
              "options": {
                "host_identifier": "hostname",
                "schedule_splay_percent": 10,
                "disable_events": false,
                "events_expiry": 3600
              },
              "file_paths": {
                "autorun": [
                  "C:\\\\Users\\\\%\\\\AppData\\\\Roaming\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup\\\\%%",
                  "C:\\\\ProgramData\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\StartUp\\\\%%"
                ]
              },
              "schedule": {
                "process_etw_events": {
                  "query": "SELECT e.path AS path, e.cmdline AS cmdline, p.name AS parent, e.pid AS pid FROM process_etw_events e LEFT JOIN processes p ON e.ppid = p.pid WHERE e.type = 'ProcessStop'",
                  "interval": 10,
                  "description": "프로세스 실행 이벤트(ETW). 종료 시점에 기록된다"
                },
                "script_etw_events": {
                  "query": "SELECT e.path AS path, e.cmdline AS cmdline, p.name AS parent, e.pid AS pid FROM process_etw_events e LEFT JOIN processes p ON e.ppid = p.pid WHERE e.type = 'ProcessStop' AND (e.path LIKE '%\\\\powershell.exe' OR e.path LIKE '%\\\\cmd.exe' OR e.path LIKE '%\\\\wscript.exe' OR e.path LIKE '%\\\\cscript.exe' OR e.path LIKE '%\\\\mshta.exe')",
                  "interval": 10,
                  "description": "스크립트 인터프리터 실행. cmdline 의 스크립트 경로로 임시/다운로드 실행을 detector 가 MEDIUM(T1059) 판정"
                },
                "file_events": {
                  "query": "SELECT path, action, time FROM ntfs_journal_events WHERE path LIKE '%\\\\Start Menu\\\\Programs\\\\Startup\\\\%'",
                  "interval": 10,
                  "description": "시작프로그램(Startup) 경로 FIM. path 로 지속성 확보를 detector 가 MEDIUM(T1547) 판정"
                }
              }
            }
            """;

    /** osquery PlatformType 비트마스크의 TYPE_WINDOWS. */
    private static final int TYPE_WINDOWS = 0x02;

    /**
     * enroll 시 저장한 platform 으로 스케줄을 고른다. Windows 면 ETW 스케줄, 그 외(darwin/미상)는 macOS.
     */
    public static String forPlatform(String platform) {
        return isWindows(platform) ? WINDOWS_JSON : MACOS_JSON;
    }

    /**
     * osquery 가 enroll 에 싣는 {@code platform_type} 은 이름이 아니라 <b>비트마스크 숫자</b>다.
     * 실기기에서 Windows 는 {@code 2}, macOS 는 {@code 21}(POSIX 1 + BSD 4 + OSX 16) 로 들어왔다.
     *
     * <p>문자열로만 보면 숫자가 전부 macOS 로 떨어져, Windows 엔드포인트가 macOS 스케줄을 받는다.
     * 그러면 {@code es_process_events} 처럼 그 OS 에 없는 테이블을 조회하게 되고, 오류 없이
     * 결과만 비어서 <b>수집이 조용히 0건</b>이 된다. 실제로 그렇게 막혔다.
     *
     * <p>이름도 함께 받는다. 값의 형태가 버전에 따라 다를 수 있고, 이름으로 오면 그쪽이 더 분명하다.
     * ("darwin" 이 "win" 을 부분문자열로 포함하므로 "windows" 로 정확히 본다.)
     */
    private static boolean isWindows(String platform) {
        if (platform == null) {
            return false;
        }
        String value = platform.trim().toLowerCase();
        if (value.contains("windows")) {
            return true;
        }
        try {
            return (Integer.parseInt(value) & TYPE_WINDOWS) != 0;
        } catch (NumberFormatException e) {
            return false;   // 이름도 숫자도 아니면 판단 근거가 없다. macOS 로 폴백한다.
        }
    }

    private OsqueryConfig() {
    }
}
