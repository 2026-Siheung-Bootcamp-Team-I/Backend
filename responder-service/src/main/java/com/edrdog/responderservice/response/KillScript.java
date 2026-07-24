package com.edrdog.responderservice.response;

/**
 * 대상 프로세스명과 "정확히 일치"하는 실행 중 프로세스만 kill 하는 POSIX sh 스크립트를 생성하는 순수 로직.
 *
 * 안전 설계:
 * - 조치 시점 호스트에서 pid 를 실시간 해석 → 탐지 시점 PID 재사용 문제 회피.
 * - comm(basename) 정확 일치(==)로만 매칭 → 부분일치/정규식 오탐 차단.
 * - 타깃을 작은따옴표로 감싸고 내부 작은따옴표를 이스케이프 → 셸 인젝션 차단.
 *
 * 한계(실제 osquery 수집 붙으면 정밀화): basename 매칭이라 같은 이름 프로세스가 여럿이면 모두 kill.
 * 전체 경로/PID+start_time 검증은 이벤트 스키마에 pid 가 실려오는 시점에 추가한다.
 */
public final class KillScript {

    private KillScript() {
    }

    /** 경로에서 파일명만 추출 ('/' 와 '\' 모두 구분자로 취급). */
    static String basename(String target) {
        if (target == null) {
            return "";
        }
        int slash = Math.max(target.lastIndexOf('/'), target.lastIndexOf('\\'));
        return slash >= 0 ? target.substring(slash + 1) : target;
    }

    /** POSIX 작은따옴표 이스케이프: ' → '\'' (닫고, 이스케이프된 따옴표, 다시 열기). */
    private static String shSingleQuote(String s) {
        return "'" + s.replace("'", "'\\''") + "'";
    }

    /** target(프로세스명 또는 경로) → 정확 일치 kill 스크립트. */
    public static String build(String target) {
        String name = shSingleQuote(basename(target));
        return """
                #!/bin/sh
                # EDRdog responder: 대상 프로세스명과 정확히 일치하는 실행 프로세스를 kill (trigger=response)
                name=%s
                pids=$(ps -Ao pid=,comm= | awk -v n="$name" '$2==n {print $1}')
                if [ -z "$pids" ]; then
                  echo "EDRDOG_RESULT=NO_MATCH name=$name"
                  exit 0
                fi
                echo "EDRDOG_RESULT=MATCH name=$name pids=$pids"
                kill $pids 2>/dev/null
                echo "EDRDOG_RESULT=KILLED name=$name pids=$pids"
                """.formatted(name);
    }
}
