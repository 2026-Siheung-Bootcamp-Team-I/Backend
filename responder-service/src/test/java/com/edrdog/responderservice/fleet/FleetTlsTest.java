package com.edrdog.responderservice.fleet;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Fleet 연결의 https 강제 판단(순수 로직).
 * 실제 조치가 켜졌을 때 평문 http 로 Bearer 토큰을 흘리지 않도록 막는 게 핵심이다.
 */
class FleetTlsTest {

    @Test
    @DisplayName("https 스킴만 https 로 인정한다(대소문자·공백 무시, null/blank 는 아님)")
    void isHttps_onlyHttpsScheme() {
        assertThat(FleetTls.isHttps("https://fleet.example")).isTrue();
        assertThat(FleetTls.isHttps("  HTTPS://fleet.example ")).isTrue();
        assertThat(FleetTls.isHttps("http://localhost:8080")).isFalse();
        assertThat(FleetTls.isHttps(null)).isFalse();
        assertThat(FleetTls.isHttps("")).isFalse();
    }

    @Test
    @DisplayName("실행 스위치가 켜졌는데 http 면 거부한다")
    void requireHttps_executingOverPlainHttp_throws() {
        assertThatThrownBy(() -> FleetTls.requireHttpsWhenExecuting("http://localhost:8080", true))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("https");
    }

    @Test
    @DisplayName("실행 스위치가 켜졌고 https 면 통과한다")
    void requireHttps_executingOverHttps_ok() {
        assertThatCode(() -> FleetTls.requireHttpsWhenExecuting("https://fleet.example", true))
                .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("실행 스위치가 꺼져 있으면(dry-run) http 여도 통과한다")
    void requireHttps_disabledOverHttp_ok() {
        assertThatCode(() -> FleetTls.requireHttpsWhenExecuting("http://localhost:8080", false))
                .doesNotThrowAnyException();
    }
}
