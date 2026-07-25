package com.edrdog.responderservice.response;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 대상 프로세스명을 안전하게 박아 정확 일치 프로세스만 kill 하는 POSIX sh 스크립트 생성 검증 (순수 로직).
 * 핵심은 셸 인젝션 차단(작은따옴표 이스케이프)과 경로→basename 정규화.
 */
class KillScriptTest {

    @Test
    @DisplayName("전체 경로 타깃은 basename 으로 매칭한다")
    void path_reducedToBasename() {
        assertThat(KillScript.basename("C:\\Windows\\System32\\powershell.exe")).isEqualTo("powershell.exe");
        assertThat(KillScript.basename("/usr/bin/curl")).isEqualTo("curl");
        assertThat(KillScript.basename("powershell.exe")).isEqualTo("powershell.exe");
    }

    @Test
    @DisplayName("타깃은 작은따옴표로 감싸 셸 인젝션을 차단한다")
    void target_singleQuotedToBlockInjection() {
        // 슬래시 없는 페이로드(있으면 basename 이 먼저 잘라냄): 작은따옴표로 조기 종료를 노림
        String script = KillScript.build("evil.exe'; rm -rf ~ #");

        // 내부 작은따옴표가 '\'' 로 이스케이프되어 조기 종료가 무력화되어야 함
        assertThat(script).contains("name='evil.exe'\\''; rm -rf ~ #'");
        assertThat(script).doesNotContain("name='evil.exe'; rm -rf ~ #'");
    }

    @Test
    @DisplayName("스크립트는 args(argv0) basename 정확 일치로만 pid 를 찾고 결과 마커를 출력한다")
    void script_exactMatchAndMarkers() {
        String script = KillScript.build("/usr/bin/powershell.exe");

        assertThat(script).startsWith("#!/bin/sh");
        assertThat(script).contains("name='powershell.exe'");
        assertThat(script).contains("ps -Ao pid=,args=");       // comm 아닌 args 사용(macOS 절단 회피)
        assertThat(script).contains("sub(/.*\\//,\"\",p)");      // argv0 → basename 정규화
        assertThat(script).contains("if (p==n)");               // basename 정확 일치
        assertThat(script).contains("kill $pids");
        assertThat(script).contains("EDRDOG_RESULT=NO_MATCH");
        assertThat(script).contains("EDRDOG_RESULT=KILLED");
    }

    @Test
    @DisplayName("comm 은 macOS 에서 전체경로+절단이라 쓰지 않는다(회귀 방지)")
    void script_doesNotUseComm() {
        String script = KillScript.build("/usr/bin/curl");

        assertThat(script).doesNotContain("comm=");
        assertThat(script).doesNotContain("$2==n");
    }
}
