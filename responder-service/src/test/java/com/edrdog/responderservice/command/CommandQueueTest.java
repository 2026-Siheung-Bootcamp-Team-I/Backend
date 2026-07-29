package com.edrdog.responderservice.command;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/** 명령 큐의 수령·결과 대기·만료·동시성 검증. */
class CommandQueueTest {

    private static final long TTL_MS = 300_000;

    /** 만료를 결정적으로 검증하려고 시각을 손으로 옮기는 시계. */
    private static final class MovableClock extends Clock {
        private Instant now = Instant.parse("2026-07-30T00:00:00Z");

        void advance(Duration d) {
            now = now.plus(d);
        }

        @Override
        public Instant instant() {
            return now;
        }

        @Override
        public ZoneId getZone() {
            return ZoneId.of("UTC");
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }
    }

    private final MovableClock clock = new MovableClock();
    private final CommandQueue queue = new CommandQueue(TTL_MS, clock);

    @Test
    @DisplayName("dispatch 한 명령이 그 호스트의 drainFor 로 나온다")
    void dispatchThenDrain() {
        String id = queue.dispatch("lab-mac", "kill_process", "/tmp/evil.sh");

        List<Command> drained = queue.drainFor("lab-mac");

        assertThat(drained).hasSize(1);
        assertThat(drained.get(0).id()).isEqualTo(id);
        assertThat(drained.get(0).type()).isEqualTo("kill_process");
        assertThat(drained.get(0).target()).isEqualTo("/tmp/evil.sh");
    }

    @Test
    @DisplayName("한 번 꺼낸 명령은 다시 나오지 않는다")
    void drainIsOnce() {
        queue.dispatch("lab-mac", "kill_process", "curl");

        assertThat(queue.drainFor("lab-mac")).hasSize(1);
        assertThat(queue.drainFor("lab-mac")).isEmpty();
    }

    @Test
    @DisplayName("다른 호스트의 명령은 섞이지 않는다")
    void hostsAreIsolated() {
        queue.dispatch("lab-mac", "kill_process", "curl");
        queue.dispatch("lab-win", "kill_process", "evil.exe");

        assertThat(queue.drainFor("lab-mac")).singleElement()
                .extracting(Command::target).isEqualTo("curl");
        assertThat(queue.drainFor("lab-win")).singleElement()
                .extracting(Command::target).isEqualTo("evil.exe");
    }

    @Test
    @DisplayName("명령이 없는 호스트는 빈 목록")
    void unknownHostIsEmpty() {
        assertThat(queue.drainFor("없는-호스트")).isEmpty();
    }

    @Test
    @DisplayName("complete 가 대기 중인 awaitResult 를 깨운다")
    void completeWakesWaiter() throws Exception {
        String id = queue.dispatch("lab-mac", "kill_process", "curl");
        CountDownLatch waiting = new CountDownLatch(1);
        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            var future = pool.submit(() -> {
                waiting.countDown();
                return queue.awaitResult(id, Duration.ofSeconds(5));
            });
            assertThat(waiting.await(2, TimeUnit.SECONDS)).isTrue();

            queue.complete(id, "KILLED", "pid 4242 종료");

            assertThat(future.get(5, TimeUnit.SECONDS)).contains("KILLED");
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    @DisplayName("결과가 awaitResult 보다 먼저 도착해도 받는다 (하트비트가 빠른 경우)")
    void completeBeforeAwait() {
        String id = queue.dispatch("lab-mac", "kill_process", "curl");
        queue.drainFor("lab-mac");

        queue.complete(id, "KILLED", "pid 4242 종료");

        assertThat(queue.awaitResult(id, Duration.ofSeconds(5))).contains("KILLED");
    }

    @Test
    @DisplayName("결과가 오지 않으면 시한 뒤 빈 값")
    void awaitTimesOut() {
        String id = queue.dispatch("lab-mac", "kill_process", "curl");

        assertThat(queue.awaitResult(id, Duration.ofMillis(100))).isEmpty();
    }

    @Test
    @DisplayName("모르는 명령 id 를 기다리면 바로 빈 값")
    void awaitUnknownId() {
        assertThat(queue.awaitResult("없는-id", Duration.ofSeconds(5))).isEmpty();
    }

    @Test
    @DisplayName("TTL 을 넘긴 명령은 drainFor 에 나오지 않는다")
    void expiredIsNotDrained() {
        queue.dispatch("lab-mac", "kill_process", "curl");

        clock.advance(Duration.ofMillis(TTL_MS + 1));

        assertThat(queue.drainFor("lab-mac")).isEmpty();
    }

    @Test
    @DisplayName("TTL 안이면 그대로 남는다")
    void notYetExpiredStays() {
        queue.dispatch("lab-mac", "kill_process", "curl");

        clock.advance(Duration.ofMillis(TTL_MS - 1));

        assertThat(queue.drainFor("lab-mac")).hasSize(1);
    }

    @Test
    @DisplayName("이미 시한을 넘긴 명령에 늦게 결과가 와도 터지지 않는다")
    void lateCompleteIsIgnored() {
        String id = queue.dispatch("lab-mac", "kill_process", "curl");
        assertThat(queue.awaitResult(id, Duration.ofMillis(50))).isEmpty();

        queue.complete(id, "KILLED", "늦은 보고");

        assertThat(queue.awaitResult(id, Duration.ofMillis(50))).isEmpty();
    }

    @Test
    @DisplayName("dispatch 와 complete 가 다른 스레드에서 동시에 일어나도 결과가 뒤섞이지 않는다")
    void concurrentDispatchAndComplete() throws Exception {
        int commands = 50;
        ExecutorService dispatchers = Executors.newFixedThreadPool(8);
        ExecutorService agent = Executors.newSingleThreadExecutor();
        AtomicInteger completed = new AtomicInteger();
        // 에이전트 역할: 큐를 계속 비우면서 각 명령을 target 과 같은 상태 문자열로 보고한다.
        // 대기 중인 요청이 자기 명령의 결과를 받았는지로 뒤섞임을 잡는다.
        agent.submit(() -> {
            while (completed.get() < commands) {
                for (Command c : queue.drainFor("lab-mac")) {
                    queue.complete(c.id(), "KILLED", c.target());
                    completed.incrementAndGet();
                }
            }
        });
        try {
            List<java.util.concurrent.Future<Optional<String>>> waits = new java.util.ArrayList<>();
            for (int i = 0; i < commands; i++) {
                waits.add(dispatchers.submit(() -> {
                    String id = queue.dispatch("lab-mac", "kill_process", "curl");
                    return queue.awaitResult(id, Duration.ofSeconds(10));
                }));
            }
            for (var w : waits) {
                assertThat(w.get(15, TimeUnit.SECONDS)).contains("KILLED");
            }
        } finally {
            dispatchers.shutdownNow();
            agent.shutdownNow();
        }
    }
}
