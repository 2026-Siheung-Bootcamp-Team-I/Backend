package com.edrdog.apiservice.geoip;

import com.edrdog.apiservice.geoip.GeoAggregator.CountryResolver;
import com.edrdog.apiservice.geoip.GeoAggregator.GeoPoint;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 목적지 IP -> 국가 집계 순수 로직 검증. resolver 를 스텁으로 주입해 mmdb 없이 검증한다.
 */
class GeoAggregatorTest {

    /** 미리 지정한 IP->ISO2 만 아는 스텁 resolver. */
    private static CountryResolver stub(Map<String, String> ipToIso) {
        return ip -> Optional.ofNullable(ipToIso.get(ip));
    }

    @Test
    void 같은_국가의_여러_IP는_건수가_합산된다() {
        Map<String, Long> counts = new LinkedHashMap<>();
        counts.put("8.8.8.8", 3L);
        counts.put("1.1.1.1", 2L);
        CountryResolver r = stub(Map.of("8.8.8.8", "US", "1.1.1.1", "US"));

        List<GeoPoint> out = GeoAggregator.aggregate(counts, r);

        assertEquals(1, out.size());
        GeoPoint us = out.get(0);
        assertEquals("US", us.countryCode());
        assertEquals("United States", us.country());
        assertEquals(5L, us.count());
    }

    @Test
    void 국가별로_나뉜다() {
        Map<String, Long> counts = new LinkedHashMap<>();
        counts.put("8.8.8.8", 4L);
        counts.put("203.0.113.9", 1L);
        CountryResolver r = stub(Map.of("8.8.8.8", "US", "203.0.113.9", "KR"));

        List<GeoPoint> out = GeoAggregator.aggregate(counts, r);

        assertEquals(2, out.size());
    }

    @Test
    void 사설IP는_resolver를_거치지않고_제외() {
        Map<String, Long> counts = new LinkedHashMap<>();
        counts.put("10.0.0.1", 9L);
        // 사설이면 애초에 집계 대상이 아니다(스텁이 US 를 줘도 무시)
        CountryResolver r = stub(Map.of("10.0.0.1", "US"));

        assertTrue(GeoAggregator.aggregate(counts, r).isEmpty());
    }

    @Test
    void geoip_미해석_IP는_제외() {
        Map<String, Long> counts = new LinkedHashMap<>();
        counts.put("8.8.8.8", 5L);
        CountryResolver r = stub(Map.of()); // 아무것도 모름

        assertTrue(GeoAggregator.aggregate(counts, r).isEmpty());
    }

    @Test
    void 중심점_없는_국가코드는_제외() {
        Map<String, Long> counts = new LinkedHashMap<>();
        counts.put("8.8.8.8", 5L);
        CountryResolver r = stub(Map.of("8.8.8.8", "ZZ")); // 중심점 맵에 없음

        assertTrue(GeoAggregator.aggregate(counts, r).isEmpty());
    }

    @Test
    void 좌표는_중심점_맵에서_채워진다() {
        Map<String, Long> counts = new LinkedHashMap<>();
        counts.put("203.0.113.9", 7L);
        CountryResolver r = stub(Map.of("203.0.113.9", "KR"));

        GeoPoint kr = GeoAggregator.aggregate(counts, r).get(0);
        CountryCentroid.Centroid expected = CountryCentroid.of("KR").orElseThrow();
        assertEquals(expected.lat(), kr.lat());
        assertEquals(expected.lng(), kr.lng());
        assertEquals(7L, kr.count());
    }
}
