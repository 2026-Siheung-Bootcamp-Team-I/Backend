package com.edrdog.responderservice.response;

/**
 * 대상 프로세스명과 "정확히 일치"하는 실행 중 프로세스만 kill 하는 POSIX sh 스크립트를 생성하는 순수 로직.
 *
 * 안전 설계:
 * - 조치 시점 호스트에서 pid 를 실시간 해석 → 탐지 시점 PID 재사용 문제 회피.
 * - 프로세스 basename 정확 일치(==)로만 매칭 → 부분일치/정규식 오탐 차단.
 * - 타깃을 작은따옴표로 감싸고 내부 작은따옴표를 이스케이프 → 셸 인젝션 차단.
 *
 * 크로스플랫폼 매칭: ps 의 comm 은 macOS 에서 전체경로 + 16자 절단이라 basename 매칭이 깨진다.
 * 그래서 args(argv0, 절단 없음)를 host 에서 basename 으로 정규화해 비교한다(Linux/macOS 공통 동작).
 *
 * 한계(실제 osquery 수집 붙으면 정밀화): basename 매칭이라 같은 이름 프로세스가 여럿이면 모두 kill.
 * argv0 경로에 공백이 있으면(예: macOS 앱번들 "…/Slack Helper.app/…/Slack Helper") ps args 의 첫
 * 토큰이 공백에서 끊겨, 그 prefix 의 basename 으로 비교되어 형제 프로세스까지 과다매칭될 수 있다.
 * 정밀 매칭(공백 경로/PID+start_time)은 osquery processes 테이블을 조회하는 시점에 추가한다.
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
                # EDRdog responder: 대상 프로세스명(basename)과 일치하는 실행 프로세스를 kill (trigger=response)
                # args(argv0)를 basename 으로 정규화해 매칭한다(comm 은 macOS 에서 전체경로+절단이라 못 씀).
                name=%s
                pids=$(ps -Ao pid=,args= | awk -v n="$name" '{p=$2; sub(/.*\\//,"",p); if (p==n) print $1}')
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
