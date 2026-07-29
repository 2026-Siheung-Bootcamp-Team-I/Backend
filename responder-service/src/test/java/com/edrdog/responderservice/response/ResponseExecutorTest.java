package com.edrdog.responderservice.response;

import com.edrdog.responderservice.command.Command;
import com.edrdog.responderservice.command.CommandQueue;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 실행 스위치·쿨다운·결과 해석 검증. 에이전트는 큐를 비우고 상태를 보고하는 스레드로 흉내낸다.
 */
class ResponseExecutorTest {

    private static final long TTL_MS = 300_000;
    private static final long TIMEOUT_MS = 2_000;

    private final CommandQueue queue = new CommandQueue(TTL_MS, Clock.systemUTC());
    private final ExecutorService agent = Executors.newSingleThreadExecutor();

    @AfterEach
    void stopAgent() {
        agent.shutdownNow();
    }

    /** 하트비트로 명령을 가져가 주어진 상태를 보고하는 가짜 에이전트. */
    private void agentReports(String host, String status) {
        agent.submit(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                List<Command> drained = queue.drainFor(host);
                for (Command c : drained) {
                    queue.complete(c.id(), status, "테스트");
                }
                if (!drained.isEmpty()) {
                    return;
                }
            }
        });
    }

    private ResponseExecutor executor(boolean enabled, long cooldownMs) {
        return new ResponseExecutor(queue, enabled, cooldownMs, TIMEOUT_MS);
    }

    @Test
    @DisplayName("실행 스위치 OFF 면 명령을 만들지 않고 DISABLED")
    void disabled_noCommand() {
        ExecuteResult result = executor(false, 60_000).killProcess("lab-win", "powershell.exe");

        assertThat(result.status()).isEqualTo("DISABLED");
        assertThat(result.executionId()).isNull();
        assertThat(queue.drainFor("lab-win")).isEmpty();
    }

    @Test
    @DisplayName("같은 호스트가 쿨다운 안에 다시 오면 COOLDOWN, 명령은 한 번만 나간다")
    void cooldown_suppressesSecondCall() {
        agentReports("lab-win", "KILLED");
        ResponseExecutor executor = executor(true, 60_000);

        ExecuteResult first = executor.killProcess("lab-win", "powershell.exe");
        ExecuteResult second = executor.killProcess("lab-win", "cmd.exe");

        assertThat(first.status()).isEqualTo("KILLED");
        assertThat(second.status()).isEqualTo("COOLDOWN");
        assertThat(second.executionId()).isNull();
        assertThat(queue.drainFor("lab-win")).isEmpty();
    }

    @Test
    @DisplayName("에이전트가 KILLED 를 보고하면 KILLED 와 명령 id 를 돌려준다")
    void agentKilled() {
        agentReports("lab-mac", "KILLED");

        ExecuteResult result = executor(true, 60_000).killProcess("lab-mac", "/tmp/evil.sh");

        assertThat(result.status()).isEqualTo("KILLED");
        assertThat(result.executionId()).isNotBlank();
    }

    @Test
    @DisplayName("에이전트가 NO_MATCH 를 보고하면 NO_MATCH")
    void agentNoMatch() {
        agentReports("lab-mac", "NO_MATCH");

        ExecuteResult result = executor(true, 60_000).killProcess("lab-mac", "curl");

        assertThat(result.status()).isEqualTo("NO_MATCH");
    }

    @Test
    @DisplayName("에이전트가 모르는 상태를 보고하면 FAILED (엔드포인트 값을 그대로 믿지 않는다)")
    void unknownStatusBecomesFailed() {
        agentReports("lab-mac", "KILLED_MAYBE");

        ExecuteResult result = executor(true, 60_000).killProcess("lab-mac", "curl");

        assertThat(result.status()).isEqualTo("FAILED");
    }

    @Test
    @DisplayName("결과가 시한 안에 오지 않으면 TIMEOUT (에이전트가 안 가져감)")
    void noResult_timesOut() {
        ResponseExecutor executor = new ResponseExecutor(queue, true, 60_000, 100);

        ExecuteResult result = executor.killProcess("오프라인-호스트", "curl");

        assertThat(result.status()).isEqualTo("TIMEOUT");
        assertThat(result.executionId()).isNotBlank();
    }

    @Test
    @DisplayName("큐가 터지면 FAILED")
    void queueError_returnsFailed() {
        CommandQueue broken = new CommandQueue(TTL_MS, Clock.systemUTC()) {
            @Override
            public String dispatch(String host, String type, String target) {
                throw new IllegalStateException("큐 고장");
            }
        };
        ResponseExecutor executor = new ResponseExecutor(broken, true, 60_000, TIMEOUT_MS);

        ExecuteResult result = executor.killProcess("lab-mac", "curl");

        assertThat(result.status()).isEqualTo("FAILED");
    }
}
