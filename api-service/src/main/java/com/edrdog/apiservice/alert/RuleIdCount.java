package com.edrdog.apiservice.alert;

/**
 * ruleId 별 alert 집계 결과(Spring Data 인터페이스 projection). summary 의 카테고리 접기에 쓴다.
 */
public interface RuleIdCount {

    String getRuleId();

    long getCnt();
}
