package com.edrdog.apiservice.query;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * tenant 격리를 구조로 강제하는 WHERE 조립기 검증.
 * 조건 목록과 params 를 이 클래스만 쥐고 있어야 tenant 조건을 빠뜨린 SQL 이 나올 길이 없다.
 */
class TenantScopeTest {

    @Test
    void tenant_가_없으면_조립을_시작할_수_없다() {
        assertThrows(IllegalArgumentException.class, () -> TenantScope.of(null));
        assertThrows(IllegalArgumentException.class, () -> TenantScope.of("  "));
    }

    @Test
    void tenant_없이_만드는_공개_경로가_없다() {
        // 공개 생성자나 tenant 를 안 받는 팩터리가 생기면 격리가 다시 선택사항이 된다.
        assertEquals(0, TenantScope.class.getConstructors().length);
        List<Method> factories = Arrays.stream(TenantScope.class.getMethods())
                .filter(m -> Modifier.isStatic(m.getModifiers()))
                .filter(m -> m.getReturnType() == TenantScope.class)
                .toList();
        assertEquals(1, factories.size());
        assertArrayEquals(new Class<?>[]{String.class}, factories.get(0).getParameterTypes());
    }

    @Test
    void tenant_는_항상_첫_조건이고_값은_trim_해서_바인딩된다() {
        ClickHouseQuery q = TenantScope.of(" 7 ").toQuery("SELECT 1 FROM t");
        assertEquals("SELECT 1 FROM t WHERE tenant_id = {tenant:String}", q.sql());
        assertEquals("7", q.params().get("tenant"));
    }

    @Test
    void 나중에_넣은_조건도_tenant_뒤에_AND_로_붙는다() {
        ClickHouseQuery q = TenantScope.of("7")
                .add("host = {host:String}", "host", "h1")
                .toQuery("SELECT 1 FROM t", " LIMIT 1");
        assertEquals("SELECT 1 FROM t WHERE tenant_id = {tenant:String} AND host = {host:String} LIMIT 1", q.sql());
        assertEquals("h1", q.params().get("host"));
    }

    @Test
    void 값_없는_조건도_넣을_수_있다() {
        ClickHouseQuery q = TenantScope.of("7").add("type IN ('dns')").toQuery("SELECT 1 FROM t");
        assertTrue(q.sql().endsWith("AND type IN ('dns')"), q.sql());
        assertEquals(1, q.params().size());
    }

    @Test
    void 옵션_필터는_값이_비면_조건을_안_넣고_있으면_trim_해서_넣는다() {
        ClickHouseQuery skipped = TenantScope.of("7")
                .addIfText("host = {host:String}", "host", "  ")
                .toQuery("SELECT 1 FROM t");
        assertFalse(skipped.sql().contains("host"), skipped.sql());
        assertEquals(1, skipped.params().size());

        ClickHouseQuery applied = TenantScope.of("7")
                .addIfText("host = {host:String}", "host", " h1 ")
                .toQuery("SELECT 1 FROM t");
        assertTrue(applied.sql().contains("host = {host:String}"), applied.sql());
        assertEquals("h1", applied.params().get("host"));
    }

    @Test
    void 시간범위는_null_이면_조건을_안_넣는다() {
        ClickHouseQuery q = TenantScope.of("7")
                .addIfPresent("ts >= {from:UInt64}", "from", null)
                .addIfPresent("ts < {to:UInt64}", "to", 2000L)
                .toQuery("SELECT 1 FROM t");
        assertFalse(q.sql().contains("{from:UInt64}"), q.sql());
        assertTrue(q.sql().contains("ts < {to:UInt64}"), q.sql());
        assertEquals("2000", q.params().get("to"));
    }

    @Test
    void IN_과_NOT_IN_은_값마다_개별_바인딩이다() {
        ClickHouseQuery in = TenantScope.of("7")
                .addIn("dest_ip", "ip", List.of("1.1.1.1", "8.8.8.8"))
                .toQuery("SELECT 1 FROM t");
        assertTrue(in.sql().contains("dest_ip IN ({ip0:String}, {ip1:String})"), in.sql());
        assertEquals("1.1.1.1", in.params().get("ip0"));
        assertEquals("8.8.8.8", in.params().get("ip1"));

        ClickHouseQuery notIn = TenantScope.of("7")
                .addNotIn("id", "exc", List.of("x"))
                .toQuery("SELECT 1 FROM t");
        assertTrue(notIn.sql().contains("id NOT IN ({exc0:String})"), notIn.sql());
        assertEquals("x", notIn.params().get("exc0"));
    }

    @Test
    void 빈_목록은_IN_조건을_안_넣는다() {
        ClickHouseQuery q = TenantScope.of("7")
                .addIn("id", "inc", List.of())
                .addNotIn("id", "exc", null)
                .toQuery("SELECT 1 FROM t");
        assertFalse(q.sql().contains(" IN ("), q.sql());
        assertEquals(1, q.params().size());
    }

    @Test
    void 조건_없이_바인딩만_얹을_수도_있다() {
        // 질의어처럼 조건 문자열을 따로 조립해 넣는 자리가 있다.
        ClickHouseQuery q = TenantScope.of("7").bind("q", "gimdong").toQuery("SELECT 1 FROM t");
        assertEquals("gimdong", q.params().get("q"));
        assertFalse(q.sql().contains("gimdong"), q.sql());
    }
}
