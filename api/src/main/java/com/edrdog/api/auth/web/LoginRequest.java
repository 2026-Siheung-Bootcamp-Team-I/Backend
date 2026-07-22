package com.edrdog.api.auth.web;

/** 로그인 요청. */
public record LoginRequest(String email, String password) {
}
