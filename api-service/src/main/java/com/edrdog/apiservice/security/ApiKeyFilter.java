package com.edrdog.apiservice.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * 모든 요청 앞단에서 X-API-Key 헤더를 검증한다. 헬스체크·Swagger 는 예외(ApiKeyPolicy).
 * 판단 로직은 ApiKeyPolicy(순수)에 있고, 여기서는 HTTP 연결만 담당한다.
 *
 * <p>순서를 명시하는 이유: 이게 없으면 등록 순서가 스캔 순서에 좌우돼 환경마다 달라진다.
 * CorsFilter 보다 앞서면 여기서 낸 401 에 CORS 헤더가 안 붙고, 브라우저는 본문을 못 읽어
 * "유효한 X-API-Key 가 필요합니다" 대신 정체불명의 네트워크 오류만 받는다. 키를 잘못 맞춘
 * 배포자가 원인을 찾을 방법이 사라진다. 로컬 테스트는 통과하는데 배포에서만 그랬다.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class ApiKeyFilter extends OncePerRequestFilter {

    private static final String HEADER = "X-API-Key";

    private final ApiKeyPolicy policy;

    public ApiKeyFilter(@Value("${edrdog.api.key}") String apiKey) {
        this.policy = new ApiKeyPolicy(apiKey);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String path = request.getRequestURI();
        boolean preflight = ApiKeyPolicy.isPreflight(
                request.getMethod(),
                request.getHeader("Origin"),
                request.getHeader("Access-Control-Request-Method"));
        if (preflight || policy.isExempt(path) || policy.isAuthorized(request.getHeader(HEADER))) {
            chain.doFilter(request, response);
            return;
        }
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write("{\"error\":\"유효한 " + HEADER + " 가 필요합니다\"}");
    }
}
