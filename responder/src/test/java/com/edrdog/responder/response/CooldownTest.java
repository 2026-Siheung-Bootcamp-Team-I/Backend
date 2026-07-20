package com.edrdog.responder.response;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

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
}
