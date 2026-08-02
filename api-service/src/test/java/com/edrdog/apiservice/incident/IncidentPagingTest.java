package com.edrdog.apiservice.incident;

import com.edrdog.apiservice.auth.AuthException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** 목록 페이지네이션/호스트 필터의 순수 로직. HTTP 배선 없이 경계값만 본다. */
class IncidentPagingTest {

    @Test
    void offset_을_안_주면_처음부터다() {
        assertThat(IncidentService.resolveOffset(null)).isZero();
    }

    @Test
    void offset_은_준_값_그대로_쓴다() {
        assertThat(IncidentService.resolveOffset(0)).isZero();
        assertThat(IncidentService.resolveOffset(37)).isEqualTo(37);
        assertThat(IncidentService.resolveOffset(IncidentService.MAX_OFFSET))
                .isEqualTo(IncidentService.MAX_OFFSET);
    }

    @Test
    void 상한을_넘는_offset_은_거절한다() {
        // 조용히 상한으로 잘라내면 호출부는 "그 페이지에 데이터가 없다" 로 읽는다.
        assertThatThrownBy(() -> IncidentService.resolveOffset(IncidentService.MAX_OFFSET + 1))
                .isInstanceOf(AuthException.class)
                .extracting(e -> ((AuthException) e).getKind())
                .isEqualTo(AuthException.Kind.INVALID_INPUT);
    }

    @Test
    void 음수_offset_은_거절한다() {
        assertThatThrownBy(() -> IncidentService.resolveOffset(-1))
                .isInstanceOf(AuthException.class)
                .extracting(e -> ((AuthException) e).getKind())
                .isEqualTo(AuthException.Kind.INVALID_INPUT);
    }

    @Test
    void host_를_안_주면_모든_호스트가_통과한다() {
        assertThat(IncidentService.matchesHost("hostA", null)).isTrue();
        assertThat(IncidentService.matchesHost("hostA", "  ")).isTrue();
    }

    @Test
    void host_는_정확히_일치할_때만_통과한다() {
        assertThat(IncidentService.matchesHost("hostA", "hostA")).isTrue();
        assertThat(IncidentService.matchesHost("hostA", "hostB")).isFalse();
        assertThat(IncidentService.matchesHost("hostA", "host")).isFalse();
    }
}
