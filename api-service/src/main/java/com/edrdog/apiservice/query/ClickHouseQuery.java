package com.edrdog.apiservice.query;

import java.util.Map;

/**
 * ClickHouse 로 보낼 SQL 과 파라미터 바인딩 값. sql 안 {name:Type} 자리표시자의 값이 params[name] 에 담긴다.
 */
// 필터값을 sql 에 직접 이어붙이면 SQL 인젝션이 열린다. 값은 반드시 params 로 간다.
public record ClickHouseQuery(String sql, Map<String, String> params) {
}
