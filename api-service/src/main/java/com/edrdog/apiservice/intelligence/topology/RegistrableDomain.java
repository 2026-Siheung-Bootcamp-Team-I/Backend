package com.edrdog.apiservice.intelligence.topology;

import com.google.common.net.InternetDomainName;

import java.util.Locale;
import java.util.Optional;

/**
 * 목적지에서 등록가능 도메인(eTLD+1)을 뽑는다(순수). 서브도메인을 한 상자로 묶는 기준값이다.
 *
 * <p>뒤에서 라벨 두 개를 자르는 방식을 쓰지 않는 이유는 그게 co.kr, com.au 처럼 공개접미사가
 * 여러 라벨인 곳에서 틀리기 때문이다(api.example.co.kr 을 "co.kr" 로 묶어 버린다).
 * Guava 의 InternetDomainName 은 Public Suffix List 를 내장하고 있어 이걸 정확히 가른다.
 *
 * <p>IP, 사설 접미사(.internal), 공개접미사 자체(com)처럼 등록가능 도메인이 없는 값은 빈 결과다.
 * 여기서 억지로 무언가를 만들어 내면 관측하지 않은 묶음을 화면에 그리게 된다.
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
