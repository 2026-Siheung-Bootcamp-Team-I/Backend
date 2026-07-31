package com.edrdog.apiservice.security;

import jakarta.servlet.Filter;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.filter.CorsFilter;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * CorsFilter 가 ApiKeyFilter 보다 먼저 도는지 확인한다.
 *
 * <p>순서가 뒤집히면 ApiKeyFilter 의 401 에 CORS 헤더가 안 붙고, 브라우저는 본문을 못 읽어
 * 정체불명의 네트워크 오류만 받는다. 키를 잘못 맞춘 배포자가 원인을 찾을 방법이 사라진다.
 *
 * <p>순서를 값으로 직접 확인하는 이유: 순서를 안 박아 두면 스캔 순서에 좌우돼 환경마다 달라진다.
 * 그래서 요청을 쏘는 테스트는 로컬에서 통과하는데 배포에서만 깨졌다. 실제로 그렇게 당했다.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.ANY)
@TestPropertySource(properties = {
        "spring.kafka.listener.auto-startup=false",
        "edrdog.cors.allowed-origins=http://localhost:5173"
})
class CorsFilterOrderTest {

    private static final String ORIGIN = "http://localhost:5173";

    @Autowired
    private TestRestTemplate rest;

    @Autowired
    private ConfigurableApplicationContext ctx;

    @Test
    void CorsFilter_가_ApiKeyFilter_보다_먼저_등록된다() {
        assertThat(orderOf(CorsFilter.class)).isLessThan(orderOf(ApiKeyFilter.class));
    }

    @Test
    void ApiKeyFilter_는_순서를_명시해_둔다() {
        // 빠지면 기본값(LOWEST_PRECEDENCE)이 아니라 등록 순서에 맡겨져 환경마다 달라진다.
        assertThat(ctx.getBeanFactory().findAnnotationOnBean("apiKeyFilter", Order.class)).isNotNull();
    }

    @Test
    void API키_거부_401_에도_허용_출처_헤더가_붙는다() {
        ResponseEntity<String> res = call("/api/tenant/install-link", HttpMethod.POST);

        assertThat(res.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(res.getHeaders().getAccessControlAllowOrigin()).isEqualTo(ORIGIN);
    }

    @Test
    void 인증_필터가_내는_401_에도_허용_출처_헤더가_붙는다() {
        // API 키 예외 경로라 ApiKeyFilter 를 지나 토큰 검증에서 막힌다.
        ResponseEntity<String> res = call("/api/hosts", HttpMethod.GET);

        assertThat(res.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(res.getHeaders().getAccessControlAllowOrigin()).isEqualTo(ORIGIN);
    }

    private ResponseEntity<String> call(String path, HttpMethod method) {
        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.ORIGIN, ORIGIN);
        return rest.exchange(path, method, new HttpEntity<>(headers), String.class);
    }

    /** Spring Boot 가 필터를 줄 세울 때 쓰는 것과 같은 값(@Order)을 읽는다. */
    private int orderOf(Class<? extends Filter> type) {
        Map<String, ? extends Filter> beans = ctx.getBeansOfType(type);
        assertThat(beans).hasSize(1);
        String name = beans.keySet().iterator().next();
        Order order = ctx.getBeanFactory().findAnnotationOnBean(name, Order.class);
        assertThat(order).as("%s 에 @Order 가 없다", name).isNotNull();
        return order.value();
    }
}
