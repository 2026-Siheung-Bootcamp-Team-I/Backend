package com.edrdog.apiservice.auth.dto;

/** 로그인 요청. */
public record LoginRequest(String email, String password) {
}
