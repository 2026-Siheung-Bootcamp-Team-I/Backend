package com.edrdog.alertservice;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

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
}
