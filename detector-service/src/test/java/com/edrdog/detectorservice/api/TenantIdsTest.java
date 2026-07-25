package com.edrdog.detectorservice.api;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 인제스트 tenantId 가 api-service 의 tenant PK(양의 정수 문자열) 형식인지 검증하는 순수 로직.
 * 조회/webhook 격리가 tenant PK 문자열로 매칭되므로, 임의 문자열("tenant-a") 유입을 막는다.
 */
class TenantIdsTest {

    @Test
    @DisplayName("양의 정수 문자열은 유효한 tenant PK")
    void validPk_positiveInteger() {
        assertThat(TenantIds.isValidPk("1")).isTrue();
        assertThat(TenantIds.isValidPk("42")).isTrue();
    }

    @Test
    @DisplayName("임의 문자열·빈값·null 은 무효")
    void invalid_nonNumeric() {
        assertThat(TenantIds.isValidPk("tenant-a")).isFalse();
        assertThat(TenantIds.isValidPk("")).isFalse();
        assertThat(TenantIds.isValidPk("  ")).isFalse();
        assertThat(TenantIds.isValidPk(null)).isFalse();
    }

    @Test
    @DisplayName("0·음수·선행 0 은 무효 (PK 는 1 이상)")
    void invalid_zeroNegativeLeadingZero() {
        assertThat(TenantIds.isValidPk("0")).isFalse();
        assertThat(TenantIds.isValidPk("-1")).isFalse();
        assertThat(TenantIds.isValidPk("01")).isFalse();
    }
}
