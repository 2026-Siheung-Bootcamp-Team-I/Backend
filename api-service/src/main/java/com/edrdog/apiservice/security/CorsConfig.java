package com.edrdog.apiservice.security;

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
 *
 * <p>필터로 두고 {@link Ordered#HIGHEST_PRECEDENCE} 를 주는 이유: preflight(OPTIONS)에는
 * Authorization/X-API-Key 헤더가 붙지 않아 {@link ApiKeyFilter} 보다 뒤에 오면 401 로 막힌다.
 * CorsFilter 가 먼저 돌면 preflight 를 여기서 끝내고 인증 필터까지 가지 않는다.
 *
 * <p>허용 출처는 설정값({@code edrdog.cors.allowed-origins}, 쉼표 구분)으로만 받는다.
 * 인증은 Bearer 토큰(헤더)이라 쿠키가 필요 없어 allowCredentials 는 켜지 않는다.
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
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public CorsFilter corsFilter() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(allowedOrigins);
        config.setAllowedMethods(ALLOWED_METHODS);
        config.setAllowedHeaders(ALLOWED_HEADERS);
        config.setMaxAge(MAX_AGE_SECONDS);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", config);
        return new CorsFilter(source);
    }

    /** 쉼표로 구분된 설정값을 출처 목록으로. 빈 항목은 버린다. */
    private static List<String> parseOrigins(String raw) {
        return Arrays.stream(raw.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();
    }
}
