package com.edrdog.alertservice;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicIntegerArray;

import static org.assertj.core.api.Assertions.assertThat;

/** 키별 쿨다운 억제 검증 (순수 로직). */
class CooldownTest {

    @Test
    @DisplayName("윈도우 안 같은 키 재요청은 억제된다")
    void withinWindow_suppressed() {
        Cooldown cooldown = new Cooldown(60_000);
        assertThat(cooldown.allow("host-1|RULE", 1_000)).isTrue();
        assertThat(cooldown.allow("host-1|RULE", 30_000)).isFalse();
    }

    @Test
    @DisplayName("윈도우 밖이면 다시 통과한다")
    void afterWindow_allowed() {
        Cooldown cooldown = new Cooldown(60_000);
        cooldown.allow("host-1|RULE", 1_000);
        assertThat(cooldown.allow("host-1|RULE", 61_001)).isTrue();
    }

    @Test
    @DisplayName("키가 다르면 각각 통과한다")
    void differentKeys_independent() {
        Cooldown cooldown = new Cooldown(60_000);
        cooldown.allow("host-1|RULE", 1_000);
        assertThat(cooldown.allow("host-2|RULE", 1_000)).isTrue();
    }

    @Test
    @DisplayName("같은 host+rule 이라도 tenant 가 다르면 각각 통과한다")
    void differentTenant_sameHostRule_independent() {
        Cooldown cooldown = new Cooldown(60_000);
        assertThat(cooldown.allow("t1|host-1|RULE", 1_000)).isTrue();
        assertThat(cooldown.allow("t2|host-1|RULE", 1_000)).isTrue();
    }

    @Test
    @DisplayName("같은 tenant+host+rule 은 윈도우 안에서 억제된다")
    void sameTenantHostRule_withinWindow_suppressed() {
        Cooldown cooldown = new Cooldown(60_000);
        assertThat(cooldown.allow("t1|host-1|RULE", 1_000)).isTrue();
        assertThat(cooldown.allow("t1|host-1|RULE", 30_000)).isFalse();
    }

    @Test
    @DisplayName("forget 하면 윈도우 안이어도 다시 통과한다 (발송 실패 롤백용)")
    void forget_allowsAgainWithinWindow() {
        Cooldown cooldown = new Cooldown(60_000);
        assertThat(cooldown.allow("t1|host-1|RULE", 1_000)).isTrue();

        cooldown.forget("t1|host-1|RULE");

        assertThat(cooldown.allow("t1|host-1|RULE", 2_000)).isTrue();
    }

    @Test
    @DisplayName("forget 은 다른 키에 영향을 주지 않는다")
    void forget_otherKeysUntouched() {
        Cooldown cooldown = new Cooldown(60_000);
        cooldown.allow("t1|host-1|RULE", 1_000);
        cooldown.allow("t1|host-2|RULE", 1_000);

        cooldown.forget("t1|host-1|RULE");

        assertThat(cooldown.allow("t1|host-2|RULE", 2_000)).isFalse();
    }

    @Test
    @DisplayName("같은 키로 동시에 호출해도 정확히 하나만 통과한다")
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
                    if (cooldown.allow("t1|host-" + round + "|RULE", 1_000)) {
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
