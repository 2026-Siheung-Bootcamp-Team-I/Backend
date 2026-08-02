package com.edrdog.apiservice.security;

import com.edrdog.apiservice.web.PageHeaders;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.Arrays;
import java.util.List;

/**
 * 브라우저에서 다른 출처의 프론트가 API 를 호출할 수 있게 CORS 를 연다.
 * 허용 출처는 설정값({@code edrdog.cors.allowed-origins}, 쉼표 구분)으로만 받는다.
 */
@Configuration
public class CorsConfig {

    private static final List<String> ALLOWED_METHODS =
            List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS");

    private static final List<String> ALLOWED_HEADERS =
            List.of("Authorization", "Content-Type", "X-API-Key");

    /** preflight 결과 캐시(초). 브라우저가 매 요청마다 OPTIONS 를 보내지 않도록 한다. */
    private static final long MAX_AGE_SECONDS = 3600;

    private final List<String> allowedOrigins;

    public CorsConfig(@Value("${edrdog.cors.allowed-origins}") String allowedOrigins) {
        this.allowedOrigins = parseOrigins(allowedOrigins);
    }

    @Bean
    // ApiKeyFilter 보다 뒤로 밀리면 헤더가 안 붙는 preflight 가 401 로 막힌다.
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public CorsFilter corsFilter() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(allowedOrigins);
        config.setAllowedMethods(ALLOWED_METHODS);
        config.setAllowedHeaders(ALLOWED_HEADERS);
        // 안 올리면 서버는 정상인데 화면에서만 페이지네이션 값이 안 보인다.
        config.setExposedHeaders(PageHeaders.ALL);
        config.setMaxAge(MAX_AGE_SECONDS);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", config);
        return new CorsFilter(source);
    }

    private static List<String> parseOrigins(String raw) {
        return Arrays.stream(raw.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();
    }
}
