package com.edrdog.apiservice.security;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * 필터가 HTTP 로 옮기는 부분: 어떤 상태코드를 내고, 브라우저에 로그인창을 띄우고, 뒤로 넘기는지.
 */
class SwaggerAuthFilterTest {

    private static String basic(String user, String password) {
        return "Basic " + Base64.getEncoder()
                .encodeToString((user + ":" + password).getBytes(StandardCharsets.UTF_8));
    }

    private static MockHttpServletRequest request(String path, String authorization) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        request.setRequestURI(path);
        if (authorization != null) {
            request.addHeader("Authorization", authorization);
        }
        return request;
    }

    @Test
    void 자격증명이_없으면_401_과_함께_로그인창을_띄운다() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        new SwaggerAuthFilter("admin", "s3cret")
                .doFilter(request("/swagger-ui/index.html", null), response, chain);

        assertEquals(401, response.getStatus());
        assertNotNull(response.getHeader("WWW-Authenticate"));
        assertNull(chain.getRequest(), "뒤로 넘어가면 안 된다");
    }

    @Test
    void 자격증명이_맞으면_뒤로_넘긴다() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        new SwaggerAuthFilter("admin", "s3cret")
                .doFilter(request("/v3/api-docs", basic("admin", "s3cret")), response, chain);

        assertEquals(200, response.getStatus());
        assertNotNull(chain.getRequest(), "뒤로 넘어가야 한다");
    }

    @Test
    void 비번이_미설정이면_로그인창을_띄우지_않는다() throws Exception {
        // 띄워봤자 맞는 값이 없어서 브라우저가 무한히 되묻는다.
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        new SwaggerAuthFilter("admin", "")
                .doFilter(request("/swagger-ui.html", null), response, chain);

        assertEquals(401, response.getStatus());
        assertNull(response.getHeader("WWW-Authenticate"));
        assertNull(chain.getRequest());
    }

    @Test
    void 프론트_경로는_건드리지_않는다() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        new SwaggerAuthFilter("admin", "s3cret")
                .doFilter(request("/api/events", null), response, chain);

        assertEquals(200, response.getStatus());
        assertNotNull(chain.getRequest());
    }
}
