package com.edrdog.responderservice.fleet;

import java.util.List;

/**
 * Fleet 호스트 조회에 쓸 식별자 후보를 만드는 순수 로직.
 *
 * <p>Fleet 의 {@code /hosts/identifier/{id}} 조회는 대소문자를 구분한다. 실측으로 확인했다.
 * 같은 기기인데 {@code gimdonghyeon-ui-MacBookPro.local} 은 404, 소문자는 200이었다.
 * osquery 는 OS 가 준 hostname 을 그대로 보내고(대문자 포함) Fleet 은 소문자로 저장해서 어긋난다.
 *
 * <p>알림의 host 를 그대로 쓰면 조치가 "호스트를 찾지 못함"으로 실패한다. 원본을 먼저 시도하고
 * 다르면 소문자도 시도한다. Windows 처럼 원본이 맞는 경우를 깨뜨리지 않으려고 순서를 이렇게 둔다.
 */
public final class HostIdentifiers {

    private HostIdentifiers() {
    }

    /** 조회 순서대로의 후보. 같은 값을 두 번 조회하지 않는다. */
    public static List<String> candidates(String identifier) {
        if (identifier == null || identifier.isBlank()) {
            return List.of();
        }
        String lower = identifier.toLowerCase();
        return identifier.equals(lower) ? List.of(identifier) : List.of(identifier, lower);
    }
}
