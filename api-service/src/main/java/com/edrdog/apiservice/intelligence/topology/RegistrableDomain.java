package com.edrdog.apiservice.intelligence.topology;

import com.google.common.net.InternetDomainName;

import java.util.Locale;
import java.util.Optional;

/**
 * 목적지에서 등록가능 도메인(eTLD+1)을 뽑는다(순수). 서브도메인을 한 상자로 묶는 기준값이다.
 * 뒤에서 라벨 두 개를 자르면 co.kr 처럼 공개접미사가 여러 라벨인 곳에서 틀려 Guava 의 PSL 을 쓴다.
 * 등록가능 도메인이 없는 값은 빈 결과다. 억지로 만들면 관측하지 않은 묶음을 화면에 그리게 된다.
 */
public final class RegistrableDomain {

    private RegistrableDomain() {
    }

    public static Optional<String> of(String destination) {
        if (destination == null || destination.isBlank()) {
            return Optional.empty();
        }
        // DNS 이름은 끝점이 붙어 오기도 한다. 그대로 두면 같은 도메인이 두 그룹으로 갈린다.
        String normalized = destination.trim().toLowerCase(Locale.ROOT).replaceAll("\\.$", "");
        try {
            InternetDomainName name = InternetDomainName.from(normalized);
            if (!name.isUnderPublicSuffix()) {
                return Optional.empty();
            }
            return Optional.of(name.topPrivateDomain().toString());
        } catch (IllegalArgumentException | IllegalStateException e) {
            // 도메인 문법이 아니거나(IPv6 등) PSL 로 해석되지 않는 값. 그룹 없이 개별 목적지로 둔다.
            return Optional.empty();
        }
    }
}
