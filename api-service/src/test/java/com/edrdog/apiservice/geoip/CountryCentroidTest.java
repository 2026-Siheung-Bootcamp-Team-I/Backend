package com.edrdog.apiservice.geoip;

import com.edrdog.apiservice.geoip.CountryCentroid.Centroid;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ISO2 -> 국가 중심점 매핑 순수 로직 검증.
 */
class CountryCentroidTest {

    @Test
    void 알려진_국가는_이름과_좌표를_준다() {
        Centroid us = CountryCentroid.of("US").orElseThrow();
        assertEquals("United States", us.country());
        Centroid kr = CountryCentroid.of("KR").orElseThrow();
        assertEquals("South Korea", kr.country());
    }

    @Test
    void 소문자_코드도_찾는다() {
        assertTrue(CountryCentroid.of("kr").isPresent());
        assertTrue(CountryCentroid.of(" jp ").isPresent());
    }

    @Test
    void 없는_코드나_null은_empty() {
        assertEquals(Optional.empty(), CountryCentroid.of("ZZ"));
        assertEquals(Optional.empty(), CountryCentroid.of(null));
    }
}
