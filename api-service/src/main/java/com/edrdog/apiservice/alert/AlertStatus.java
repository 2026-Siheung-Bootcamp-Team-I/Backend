package com.edrdog.apiservice.alert;

/**
 * alert 트리아지 status 값과 검증(순수). open 은 초기값이고, PATCH 로 바꿀 수 있는 값은 confirmed / false_positive 뿐이다.
 */
public final class AlertStatus {

    public static final String OPEN = "open";
    public static final String CONFIRMED = "confirmed";
    public static final String FALSE_POSITIVE = "false_positive";

    private AlertStatus() {
    }

    public static boolean validTransition(String status) {
        return CONFIRMED.equals(status) || FALSE_POSITIVE.equals(status);
    }
}
