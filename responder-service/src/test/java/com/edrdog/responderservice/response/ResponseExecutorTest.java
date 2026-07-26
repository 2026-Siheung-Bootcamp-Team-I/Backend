package com.edrdog.responderservice.response;

import com.edrdog.responderservice.fleet.FleetClient;
import com.edrdog.responderservice.fleet.FleetHost;
import com.edrdog.responderservice.fleet.FleetScriptResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/** 실행 스위치·쿨다운·예외 가드 검증 (Fleet 호출은 목으로 대체). */
class ResponseExecutorTest {

    private final FleetClient fleet = mock(FleetClient.class);

    private FleetScriptResult killed() {
        return new FleetScriptResult("exec-1", 0, false, "EDRDOG_RESULT=KILLED name=x pids=1", "");
    }

    @Test
    @DisplayName("실행 스위치 OFF 면 Fleet 을 호출하지 않고 DISABLED")
    void disabled_noFleetCall() {
        ResponseExecutor executor = new ResponseExecutor(fleet, false, 60_000);

        ExecuteResult result = executor.killProcess("host-1", "powershell.exe");

        assertThat(result.status()).isEqualTo("DISABLED");
        verifyNoInteractions(fleet);
    }

    @Test
    @DisplayName("스위치 ON 이면 Fleet 실행 후 결과 상태를 반환")
    void enabled_runsAndReturnsOutcome() {
        when(fleet.resolveHost("host-1")).thenReturn(new FleetHost(42, "darwin"));
        when(fleet.runScriptSync(eq(42), anyString())).thenReturn(killed());
        ResponseExecutor executor = new ResponseExecutor(fleet, true, 60_000);

        ExecuteResult result = executor.killProcess("host-1", "powershell.exe");

        assertThat(result.status()).isEqualTo("KILLED");
        assertThat(result.executionId()).isEqualTo("exec-1");
    }

    @Test
    @DisplayName("같은 호스트가 쿨다운 안에 다시 오면 COOLDOWN, Fleet 은 한 번만 호출")
    void cooldown_suppressesSecondCall() {
        when(fleet.resolveHost(anyString())).thenReturn(new FleetHost(42, "darwin"));
        when(fleet.runScriptSync(anyInt(), anyString())).thenReturn(killed());
        ResponseExecutor executor = new ResponseExecutor(fleet, true, 60_000);

        executor.killProcess("host-1", "powershell.exe");
        ExecuteResult second = executor.killProcess("host-1", "cmd.exe");

        assertThat(second.status()).isEqualTo("COOLDOWN");
        verify(fleet, times(1)).runScriptSync(anyInt(), anyString());
    }

    @Test
    @DisplayName("Fleet 호출이 실패하면 FAILED")
    void fleetError_returnsFailed() {
        when(fleet.resolveHost(anyString())).thenThrow(new IllegalStateException("호스트 없음"));
        ResponseExecutor executor = new ResponseExecutor(fleet, true, 60_000);

        ExecuteResult result = executor.killProcess("host-1", "powershell.exe");

        assertThat(result.status()).isEqualTo("FAILED");
    }

    @Test
    @DisplayName("Windows 호스트에는 PowerShell 스크립트를 보낸다 (POSIX sh 는 Windows 에서 실패한다)")
    void windowsHost_sendsPowerShell() {
        when(fleet.resolveHost("win-1")).thenReturn(new FleetHost(7, "windows"));
        when(fleet.runScriptSync(eq(7), anyString())).thenReturn(killed());
        ResponseExecutor executor = new ResponseExecutor(fleet, true, 60_000);

        executor.killProcess("win-1", "evil.exe");

        ArgumentCaptor<String> script = ArgumentCaptor.forClass(String.class);
        verify(fleet).runScriptSync(eq(7), script.capture());
        assertThat(script.getValue()).contains("Stop-Process");
        assertThat(script.getValue()).doesNotContain("#!/bin/sh");
    }

    @Test
    @DisplayName("macOS 호스트에는 POSIX sh 를 보낸다")
    void macHost_sendsPosix() {
        when(fleet.resolveHost("mac-1")).thenReturn(new FleetHost(8, "darwin"));
        when(fleet.runScriptSync(eq(8), anyString())).thenReturn(killed());
        ResponseExecutor executor = new ResponseExecutor(fleet, true, 60_000);

        executor.killProcess("mac-1", "curl");

        ArgumentCaptor<String> script = ArgumentCaptor.forClass(String.class);
        verify(fleet).runScriptSync(eq(8), script.capture());
        assertThat(script.getValue()).startsWith("#!/bin/sh");
    }
}
