package com.edrdog.apiservice.auth.service;

/**
 * 회원가입/로그인 입력 검증(순수). 해커톤 수준의 최소 규칙만 둔다.
 */
public final class AuthValidation {

    private AuthValidation() {
    }

    public static boolean validEmail(String email) {
        return email != null && email.contains("@") && email.contains(".");
    }

    public static boolean validPassword(String password) {
        return password != null && password.length() >= 8;
    }
}
