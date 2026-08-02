package com.edrdog.detectorservice.api;

import java.util.regex.Pattern;

/** 인제스트 tenantId 검증(순수). 양의 정수가 아니면 alert 조회/webhook 격리 매칭이 어긋난다. */
public final class TenantIds {

    private static final Pattern POSITIVE_INT = Pattern.compile("[1-9][0-9]*");

    private TenantIds() {
    }

    /** 양의 정수 문자열(선행 0 없음)만 유효한 tenant PK 로 본다. */
    public static boolean isValidPk(String tenantId) {
        return tenantId != null && POSITIVE_INT.matcher(tenantId).matches();
    }
}
