package com.edrdog.api.geoip;

import java.util.Map;
import java.util.Optional;

/**
 * ISO2 국가 코드 -> {표시 이름, 중심 위/경도} 매핑(순수). world map 마커 좌표로 쓴다.
 * 지도 표시에 충분한 주요 국가 위주이며, 없는 코드는 Optional.empty.
 */
public final class CountryCentroid {

    /** 국가 중심점. lat 위도, lng 경도(도 단위). */
    public record Centroid(String country, double lat, double lng) {
    }

    private static final Map<String, Centroid> BY_ISO2 = Map.ofEntries(
            Map.entry("US", new Centroid("United States", 37.09, -95.71)),
            Map.entry("CA", new Centroid("Canada", 56.13, -106.35)),
            Map.entry("MX", new Centroid("Mexico", 23.63, -102.55)),
            Map.entry("BR", new Centroid("Brazil", -14.24, -51.93)),
            Map.entry("AR", new Centroid("Argentina", -38.42, -63.62)),
            Map.entry("CL", new Centroid("Chile", -35.68, -71.54)),
            Map.entry("CO", new Centroid("Colombia", 4.57, -74.30)),
            Map.entry("GB", new Centroid("United Kingdom", 55.38, -3.44)),
            Map.entry("IE", new Centroid("Ireland", 53.41, -8.24)),
            Map.entry("FR", new Centroid("France", 46.23, 2.21)),
            Map.entry("DE", new Centroid("Germany", 51.17, 10.45)),
            Map.entry("NL", new Centroid("Netherlands", 52.13, 5.29)),
            Map.entry("BE", new Centroid("Belgium", 50.50, 4.47)),
            Map.entry("ES", new Centroid("Spain", 40.46, -3.75)),
            Map.entry("PT", new Centroid("Portugal", 39.40, -8.22)),
            Map.entry("IT", new Centroid("Italy", 41.87, 12.57)),
            Map.entry("CH", new Centroid("Switzerland", 46.82, 8.23)),
            Map.entry("AT", new Centroid("Austria", 47.52, 14.55)),
            Map.entry("SE", new Centroid("Sweden", 60.13, 18.64)),
            Map.entry("NO", new Centroid("Norway", 60.47, 8.47)),
            Map.entry("FI", new Centroid("Finland", 61.92, 25.75)),
            Map.entry("DK", new Centroid("Denmark", 56.26, 9.50)),
            Map.entry("PL", new Centroid("Poland", 51.92, 19.15)),
            Map.entry("CZ", new Centroid("Czechia", 49.82, 15.47)),
            Map.entry("RO", new Centroid("Romania", 45.94, 24.97)),
            Map.entry("UA", new Centroid("Ukraine", 48.38, 31.17)),
            Map.entry("RU", new Centroid("Russia", 61.52, 105.32)),
            Map.entry("TR", new Centroid("Turkey", 38.96, 35.24)),
            Map.entry("IL", new Centroid("Israel", 31.05, 34.85)),
            Map.entry("SA", new Centroid("Saudi Arabia", 23.89, 45.08)),
            Map.entry("AE", new Centroid("United Arab Emirates", 23.42, 53.85)),
            Map.entry("ZA", new Centroid("South Africa", -30.56, 22.94)),
            Map.entry("NG", new Centroid("Nigeria", 9.08, 8.68)),
            Map.entry("EG", new Centroid("Egypt", 26.82, 30.80)),
            Map.entry("KE", new Centroid("Kenya", -0.02, 37.91)),
            Map.entry("IN", new Centroid("India", 20.59, 78.96)),
            Map.entry("PK", new Centroid("Pakistan", 30.38, 69.35)),
            Map.entry("CN", new Centroid("China", 35.86, 104.20)),
            Map.entry("HK", new Centroid("Hong Kong", 22.32, 114.17)),
            Map.entry("TW", new Centroid("Taiwan", 23.70, 120.96)),
            Map.entry("JP", new Centroid("Japan", 36.20, 138.25)),
            Map.entry("KR", new Centroid("South Korea", 35.91, 127.77)),
            Map.entry("SG", new Centroid("Singapore", 1.35, 103.82)),
            Map.entry("MY", new Centroid("Malaysia", 4.21, 101.98)),
            Map.entry("TH", new Centroid("Thailand", 15.87, 100.99)),
            Map.entry("VN", new Centroid("Vietnam", 14.06, 108.28)),
            Map.entry("ID", new Centroid("Indonesia", -0.79, 113.92)),
            Map.entry("PH", new Centroid("Philippines", 12.88, 121.77)),
            Map.entry("AU", new Centroid("Australia", -25.27, 133.78)),
            Map.entry("NZ", new Centroid("New Zealand", -40.90, 174.89)));

    private CountryCentroid() {
    }

    /** ISO2 코드(대소문자 무관)의 중심점. 없으면 empty. */
    public static Optional<Centroid> of(String iso2) {
        if (iso2 == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(BY_ISO2.get(iso2.trim().toUpperCase()));
    }
}
