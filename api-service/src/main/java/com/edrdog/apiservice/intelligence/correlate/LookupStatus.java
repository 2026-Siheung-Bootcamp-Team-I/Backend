package com.edrdog.apiservice.intelligence.correlate;

/** 실시간 DNS 조회 한 건의 결과 상태. 실패를 예외 대신 200 응답 안에 담기 위해 있다. */
public enum LookupStatus {
    /** 답이 왔다. */
    OK,
    /** 서버가 "그런 이름 없다"고 답했다. 조회 자체는 성공이다. */
    NOT_FOUND,
    /** 타임아웃·네트워크 오류 등으로 묻지 못했다. 없다는 뜻이 아니다. */
    FAILED
}
