package com.edrdog.apiservice.security;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Swagger 를 가리는 Basic 인증의 판단 로직(순수): 어떤 경로를 막고, 어떤 헤더를 통과시키는지.
 */
class SwaggerAuthPolicyTest {

    private final SwaggerAuthPolicy policy = new SwaggerAuthPolicy("admin", "s3cret");

    private static String basic(String user, String password) {
        String raw = user + ":" + password;
        return "Basic " + Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void swagger_와_api_docs_는_보호_대상() {
        assertTrue(policy.isProtected("/swagger-ui.html"));
        assertTrue(policy.isProtected("/swagger-ui/index.html"));
        assertTrue(policy.isProtected("/v3/api-docs"));
        assertTrue(policy.isProtected("/v3/api-docs/swagger-config"));
    }

    @Test
    void 프론트와_헬스체크_경로는_보호_대상이_아니다() {
        assertFalse(policy.isProtected("/api/events"));
        assertFalse(policy.isProtected("/api/auth/login"));
        assertFalse(policy.isProtected("/actuator/health"));
        assertFalse(policy.isProtected("/i/abc123"));
    }

    @Test
    void 계정이_맞으면_통과() {
        assertTrue(policy.isAuthorized(basic("admin", "s3cret")));
    }

    @Test
    void 스킴은_대소문자를_가리지_않는다() {
        assertTrue(policy.isAuthorized(basic("admin", "s3cret").replace("Basic", "basic")));
    }

    @Test
    void 비번이나_아이디가_틀리면_거부() {
        assertFalse(policy.isAuthorized(basic("admin", "wrong")));
        assertFalse(policy.isAuthorized(basic("root", "s3cret")));
    }

    @Test
    void 헤더가_없거나_Basic_이_아니면_거부() {
        assertFalse(policy.isAuthorized(null));
        assertFalse(policy.isAuthorized(""));
        assertFalse(policy.isAuthorized("Bearer eyJhbGciOi"));
    }

    @Test
    void 깨진_base64_나_구분자가_없으면_거부() {
        assertFalse(policy.isAuthorized("Basic !!!not-base64!!!"));
        assertFalse(policy.isAuthorized("Basic " + Base64.getEncoder()
                .encodeToString("구분자없음".getBytes(StandardCharsets.UTF_8))));
    }

    @Test
    void 비번이_비어_있으면_아무도_통과하지_못한다() {
        // Infisical 이 값을 못 주면 열린 채로 두지 않고 전부 막는다.
        SwaggerAuthPolicy 미설정 = new SwaggerAuthPolicy("admin", "");
        assertFalse(미설정.isAuthorized(basic("admin", "")));
        assertFalse(미설정.isAuthorized(basic("admin", "아무거나")));
    }

    @Test
    void 비번이_설정됐는지_따로_알려준다() {
        // 미설정이면 인증을 요구해도 답할 방법이 없다. 그때 팝업을 띄우면 브라우저가 무한히 되묻는다.
        assertTrue(policy.isConfigured());
        assertFalse(new SwaggerAuthPolicy("admin", "").isConfigured());
        assertFalse(new SwaggerAuthPolicy("admin", null).isConfigured());
    }

    @Test
    void 비번에_콜론이_있어도_뒤쪽_전부를_비번으로_본다() {
        SwaggerAuthPolicy 콜론 = new SwaggerAuthPolicy("admin", "a:b:c");
        assertTrue(콜론.isAuthorized(basic("admin", "a:b:c")));
    }
}
