package com.edrdog.apiservice.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * 모든 요청 앞단에서 X-API-Key 헤더를 검증한다. 헬스체크·Swagger 는 예외(ApiKeyPolicy).
 * 판단 로직은 ApiKeyPolicy(순수)에 있고, 여기서는 HTTP 연결만 담당한다.
 */
@Component
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
        if (policy.isExempt(path) || policy.isAuthorized(request.getHeader(HEADER))) {
            chain.doFilter(request, response);
            return;
        }
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write("{\"error\":\"유효한 " + HEADER + " 가 필요합니다\"}");
    }
}
