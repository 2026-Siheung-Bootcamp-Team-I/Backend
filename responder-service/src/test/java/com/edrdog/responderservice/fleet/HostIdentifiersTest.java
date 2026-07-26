package com.edrdog.responderservice.fleet;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Fleet 호스트 조회에 쓸 식별자 후보 (순수 로직).
 *
 * <p>Fleet 의 identifier 조회는 대소문자를 구분한다. 실측: 같은 기기인데
 * "gimdonghyeon-ui-MacBookPro.local" 은 404, "gimdonghyeon-ui-macbookpro.local" 은 200.
 * osquery 는 OS 가 준 이름을 그대로 보내고 Fleet 은 소문자로 저장해서 어긋난다.
 */
class HostIdentifiersTest {

    @Test
    @DisplayName("대문자가 섞여 있으면 원본과 소문자를 함께 후보로 낸다")
    void mixedCase_yieldsBothCandidates() {
        List<String> c = HostIdentifiers.candidates("gimdonghyeon-ui-MacBookPro.local");

        assertThat(c).containsExactly("gimdonghyeon-ui-MacBookPro.local", "gimdonghyeon-ui-macbookpro.local");
    }

    @Test
    @DisplayName("이미 소문자면 후보는 하나뿐 (같은 조회를 두 번 하지 않는다)")
    void lowerCase_yieldsSingleCandidate() {
        assertThat(HostIdentifiers.candidates("srv-web-01")).containsExactly("srv-web-01");
    }

    @Test
    @DisplayName("Windows 처럼 전부 대문자여도 원본을 먼저 시도한다")
    void upperCase_triesOriginalFirst() {
        assertThat(HostIdentifiers.candidates("DESKTOP-KIM"))
                .containsExactly("DESKTOP-KIM", "desktop-kim");
    }

    @Test
    @DisplayName("비어 있으면 후보 없음")
    void blank_yieldsNothing() {
        assertThat(HostIdentifiers.candidates(null)).isEmpty();
        assertThat(HostIdentifiers.candidates("  ")).isEmpty();
    }
}
