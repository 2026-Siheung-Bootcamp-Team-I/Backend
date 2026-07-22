package com.edrdog.api.query;

import java.util.Map;

/**
 * ClickHouse 로 보낼 SQL 과 파라미터 바인딩 값.
 * sql 안의 {name:Type} 자리표시자에 대응하는 값이 params[name] 에 담긴다(HTTP param_name 으로 전송).
 * 필터값을 SQL 문자열에 직접 이어붙이지 않아 SQL 인젝션을 막는다.
 */
public record ClickHouseQuery(String sql, Map<String, String> params) {
}
