package com.edrdog.apiservice.query;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * tenant 로 잠긴 WHERE 조립기. 조건과 파라미터를 이 객체만 쥐고 있고, 만드는 길이 {@link #of(String)} 하나뿐이라
 * 빌더가 tenant 조건을 빠뜨린 조회를 만들 수 없다.
 */
// 새 빌더가 격리를 다시 손으로 적지 않게 하는 것이 이 클래스의 존재 이유다. 공개 생성자나
// tenant 를 안 받는 팩터리를 열면 격리가 다시 선택사항이 된다.
public final class TenantScope {

    private final List<String> conds = new ArrayList<>();
    private final Map<String, String> params = new LinkedHashMap<>();

    private TenantScope(String tenantId) {
        // 이 검사를 빼면 tenant 없는 호출이 조직 전체를 그대로 읽는다.
        if (!QueryGuards.hasText(tenantId)) {
            throw new IllegalArgumentException("tenant 는 필수입니다(격리)");
        }
        // tenant 격리는 항상 첫 조건으로 강제한다.
        conds.add("tenant_id = {tenant:String}");
        params.put("tenant", tenantId.trim());
    }

    public static TenantScope of(String tenantId) {
        return new TenantScope(tenantId);
    }

    /** 값이 없는 조건(상수 조건). */
    public TenantScope add(String cond) {
        conds.add(cond);
        return this;
    }

    /** 조건과 그 값의 바인딩을 함께 넣는다. 값은 준 그대로 바인딩한다(정규화는 호출부 몫). */
    public TenantScope add(String cond, String name, String value) {
        conds.add(cond);
        params.put(name, value);
        return this;
    }

    /** 옵션 필터. 값이 비어 있으면 조건 자체를 걸지 않고, 있으면 trim 해서 바인딩한다. */
    public TenantScope addIfText(String cond, String name, String value) {
        if (QueryGuards.hasText(value)) {
            add(cond, name, value.trim());
        }
        return this;
    }

    /** 시간 범위처럼 null 이면 제한하지 않는 조건. */
    public TenantScope addIfPresent(String cond, String name, Long value) {
        if (value != null) {
            add(cond, name, String.valueOf(value));
        }
        return this;
    }

    /** 값 목록을 개별 바인딩으로 푼 IN 조건. 비어 있으면 아무것도 안 한다. */
    public TenantScope addIn(String column, String key, List<String> values) {
        return addSet(column, key, values, false);
    }

    /** addIn 의 반대. 트리아지된 alert 를 빼는 자리에 쓴다. */
    public TenantScope addNotIn(String column, String key, List<String> values) {
        return addSet(column, key, values, true);
    }

    /** 조건 문자열을 호출부가 따로 조립하는 경우의 값 바인딩(질의어 등). */
    public TenantScope bind(String name, String value) {
        params.put(name, value);
        return this;
    }

    /** head 와 tail 사이에 WHERE 를 끼워 조회를 만든다. params 를 꺼낼 길이 여기뿐이다. */
    public ClickHouseQuery toQuery(String head, String tail) {
        return new ClickHouseQuery(head + " WHERE " + String.join(" AND ", conds) + tail, params);
    }

    public ClickHouseQuery toQuery(String head) {
        return toQuery(head, "");
    }

    private TenantScope addSet(String column, String key, List<String> values, boolean negate) {
        if (values == null || values.isEmpty()) {
            return this;
        }
        List<String> placeholders = new ArrayList<>();
        for (int i = 0; i < values.size(); i++) {
            String name = key + i;
            placeholders.add("{" + name + ":String}");
            params.put(name, values.get(i));
        }
        conds.add(column + (negate ? " NOT IN (" : " IN (") + String.join(", ", placeholders) + ")");
        return this;
    }
}
