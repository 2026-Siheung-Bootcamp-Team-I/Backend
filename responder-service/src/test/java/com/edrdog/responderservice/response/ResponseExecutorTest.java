package com.edrdog.responderservice.response;

import com.edrdog.responderservice.fleet.FleetClient;
import com.edrdog.responderservice.fleet.FleetScriptResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

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
        when(fleet.resolveHostId("host-1")).thenReturn(42);
        when(fleet.runScriptSync(eq(42), anyString())).thenReturn(killed());
        ResponseExecutor executor = new ResponseExecutor(fleet, true, 60_000);

        ExecuteResult result = executor.killProcess("host-1", "powershell.exe");

        assertThat(result.status()).isEqualTo("KILLED");
        assertThat(result.executionId()).isEqualTo("exec-1");
    }

    @Test
    @DisplayName("같은 호스트가 쿨다운 안에 다시 오면 COOLDOWN, Fleet 은 한 번만 호출")
    void cooldown_suppressesSecondCall() {
        when(fleet.resolveHostId(anyString())).thenReturn(42);
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
        when(fleet.resolveHostId(anyString())).thenThrow(new IllegalStateException("호스트 없음"));
        ResponseExecutor executor = new ResponseExecutor(fleet, true, 60_000);

        ExecuteResult result = executor.killProcess("host-1", "powershell.exe");

        assertThat(result.status()).isEqualTo("FAILED");
    }
}
