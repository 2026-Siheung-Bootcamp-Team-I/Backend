package com.edrdog.apiservice.geoip;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * 목적지 IP 별 건수를 국가 단위로 합산하는 순수 로직. resolver(ip -> ISO2)를 함수형으로 주입받아
 * 실제 mmdb 없이도 테스트 가능하다. 비공인 IP, geoip 미해석, 중심점 없는 국가는 건너뛴다.
 */
public final class GeoAggregator {

    /** world map 마커 한 점. */
    public record GeoPoint(String country, String countryCode, double lat, double lng, long count) {
    }

    /** IP -> ISO2 국가 코드 해석기(없으면 empty). GeoIpResolver::countryCode 를 넘긴다. */
    @FunctionalInterface
    public interface CountryResolver {
        Optional<String> countryCode(String ip);
    }

    private GeoAggregator() {
    }

    /**
     * ipCounts(목적지 IP -> 건수)를 국가별로 합산한다.
     * 각 IP 는 공인이어야 하고(PrivateIp), resolver 가 ISO2 를 주고, 그 ISO2 가 중심점 맵에 있어야 집계된다.
     */
    public static List<GeoPoint> aggregate(Map<String, Long> ipCounts, CountryResolver resolver) {
        Map<String, Long> byCountry = new LinkedHashMap<>();
        for (Map.Entry<String, Long> e : ipCounts.entrySet()) {
            String ip = e.getKey();
            if (!PrivateIp.isPublic(ip)) {
                continue;
            }
            Optional<String> iso = resolver.countryCode(ip);
            if (iso.isEmpty()) {
                continue;
            }
            String code = iso.get().trim().toUpperCase();
            if (CountryCentroid.of(code).isEmpty()) {
                continue;
            }
            byCountry.merge(code, e.getValue(), Long::sum);
        }

        List<GeoPoint> out = new ArrayList<>();
        for (Map.Entry<String, Long> e : byCountry.entrySet()) {
            CountryCentroid.Centroid c = CountryCentroid.of(e.getKey()).orElseThrow();
            out.add(new GeoPoint(c.country(), e.getKey(), c.lat(), c.lng(), e.getValue()));
        }
        return out;
    }
}
