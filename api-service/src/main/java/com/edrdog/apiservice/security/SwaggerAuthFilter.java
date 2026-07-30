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
 * Swagger 경로를 Basic 인증으로 가린다. 판단은 SwaggerAuthPolicy(순수), 여기서는 HTTP 만 담당한다.
 *
 * <p>어느 필터가 401 을 냈는지 헷갈리지 않게 ApiKeyFilter 보다 먼저 돌도록 고정한다.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class SwaggerAuthFilter extends OncePerRequestFilter {

    private final SwaggerAuthPolicy policy;

    public SwaggerAuthFilter(@Value("${edrdog.swagger.user}") String user,
                             @Value("${edrdog.swagger.password}") String password) {
        this.policy = new SwaggerAuthPolicy(user, password);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String path = request.getRequestURI();
        if (!policy.isProtected(path) || policy.isAuthorized(request.getHeader("Authorization"))) {
            chain.doFilter(request, response);
            return;
        }
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        if (policy.isConfigured()) {
            // 이 헤더가 있어야 브라우저가 아이디/비번 입력창을 띄운다.
            response.setHeader("WWW-Authenticate", "Basic realm=\"EDRdog Swagger\", charset=\"UTF-8\"");
            response.getWriter().write("{\"error\":\"Swagger 는 로그인이 필요합니다\"}");
        } else {
            response.getWriter().write(
                    "{\"error\":\"EDRDOG_SWAGGER_PASSWORD 가 설정되지 않아 Swagger 를 닫아 두었습니다\"}");
        }
    }
}
