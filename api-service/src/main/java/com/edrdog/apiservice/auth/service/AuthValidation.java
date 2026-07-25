package com.edrdog.apiservice.auth.service;

/**
 * 회원가입/로그인 입력 검증(순수). 해커톤 수준의 최소 규칙만 둔다.
 */
public final class AuthValidation {

    private AuthValidation() {
    }

    /** null 아님 + '@' 포함 + '.' 포함이면 유효한 이메일로 본다. */
    public static boolean validEmail(String email) {
        return email != null && email.contains("@") && email.contains(".");
    }

    /** null 아님 + 길이 8 이상이면 유효한 비밀번호로 본다. */
    public static boolean validPassword(String password) {
        return password != null && password.length() >= 8;
    }
}
