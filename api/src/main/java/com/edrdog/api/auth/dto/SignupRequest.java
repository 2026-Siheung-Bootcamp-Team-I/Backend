package com.edrdog.api.auth.dto;

/** 회원가입 요청. orgName 은 선택(없으면 이메일 로컬파트로 조직명 생성). */
public record SignupRequest(String email, String password, String orgName) {
}
