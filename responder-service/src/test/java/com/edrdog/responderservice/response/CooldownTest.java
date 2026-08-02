package com.edrdog.responderservice.response;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicIntegerArray;

import static org.assertj.core.api.Assertions.assertThat;

/** 같은 키의 중복 표시를 윈도우 동안 억제하는 쿨다운 순수 로직 검증. */
class CooldownTest {

    @Test
    @DisplayName("첫 호출은 통과")
    void firstAllow() {
        Cooldown cooldown = new Cooldown(60_000);
        assertThat(cooldown.allow("host-1|kill", 1_000)).isTrue();
    }

    @Test
    @DisplayName("윈도우 안 같은 키 재호출은 억제")
    void withinWindow_suppressed() {
        Cooldown cooldown = new Cooldown(60_000);
        cooldown.allow("host-1|kill", 1_000);
        assertThat(cooldown.allow("host-1|kill", 60_000)).isFalse();
    }

    @Test
    @DisplayName("윈도우 경과 후 같은 키는 다시 통과")
    void afterWindow_allowed() {
        Cooldown cooldown = new Cooldown(60_000);
        cooldown.allow("host-1|kill", 1_000);
        assertThat(cooldown.allow("host-1|kill", 61_000)).isTrue();
    }

    @Test
    @DisplayName("키가 다르면 서로 독립적으로 통과")
    void differentKeys_independent() {
        Cooldown cooldown = new Cooldown(60_000);
        cooldown.allow("host-1|kill", 1_000);
        assertThat(cooldown.allow("host-1|isolate", 1_000)).isTrue();
        assertThat(cooldown.allow("host-2|kill", 1_000)).isTrue();
    }

    @Test
    @DisplayName("같은 키로 동시에 호출해도 정확히 하나만 통과")
    void concurrentSameKey_onlyOnePasses() throws Exception {
        int threads = 8;
        int rounds = 500;
        Cooldown cooldown = new Cooldown(60_000);
        AtomicIntegerArray passed = new AtomicIntegerArray(rounds);
        // 라운드마다 배리어로 출발선을 맞춰야 판정과 갱신 사이의 경합이 실제로 생긴다.
        CyclicBarrier barrier = new CyclicBarrier(threads);
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        for (int t = 0; t < threads; t++) {
            pool.submit(() -> {
                for (int round = 0; round < rounds; round++) {
                    barrier.await();
                    if (cooldown.allow("host-" + round + "|kill", 1_000)) {
                        passed.incrementAndGet(round);
                    }
                }
                return null;
            });
        }
        pool.shutdown();
        assertThat(pool.awaitTermination(30, TimeUnit.SECONDS)).isTrue();

        for (int round = 0; round < rounds; round++) {
            assertThat(passed.get(round)).as("round %d", round).isEqualTo(1);
        }
    }
}
