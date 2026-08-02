package com.edrdog.apiservice.tenant;

import com.edrdog.apiservice.auth.Tenant;
import com.edrdog.apiservice.auth.AuthException;
import com.edrdog.apiservice.auth.TenantRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * TenantService: 리포지토리는 목킹, WebhookValidation 은 실제로 사용.
 */
class TenantServiceTest {

    private TenantRepository tenants;
    private TenantService service;

    @BeforeEach
    void setUp() {
        tenants = mock(TenantRepository.class);
        service = new TenantService(tenants);
    }

    private static Tenant newTenant() {
        return Tenant.of("org", Instant.now());
    }

    @Test
    void setWebhook_검증통과하면_저장() {
        Tenant t = newTenant();
        when(tenants.findById(10L)).thenReturn(Optional.of(t));

        service.setWebhook(10L, "https://hooks.slack.com/services/xxx");

        assertEquals("https://hooks.slack.com/services/xxx", t.getSlackWebhookUrl());
        verify(tenants).save(any(Tenant.class));
    }

    @Test
    void setWebhook_잘못된URL이면_400예외() {
        AuthException e = assertThrows(AuthException.class,
                () -> service.setWebhook(10L, "http://not-https"));
        assertEquals(AuthException.Kind.INVALID_INPUT, e.getKind());
    }

    @Test
    void setWebhook_tenant없으면_404예외() {
        when(tenants.findById(99L)).thenReturn(Optional.empty());

        AuthException e = assertThrows(AuthException.class,
                () -> service.setWebhook(99L, "https://hooks.slack.com/services/xxx"));
        assertEquals(AuthException.Kind.NOT_FOUND, e.getKind());
    }

    @Test
    void getWebhook_저장된값_반환() {
        Tenant t = newTenant();
        t.updateWebhook("https://hooks.slack.com/services/xxx");
        when(tenants.findById(10L)).thenReturn(Optional.of(t));

        Optional<String> url = service.getWebhook(10L);

        assertTrue(url.isPresent());
        assertEquals("https://hooks.slack.com/services/xxx", url.get());
    }

    @Test
    void getWebhook_미설정이면_빈값() {
        when(tenants.findById(10L)).thenReturn(Optional.of(newTenant()));

        assertFalse(service.getWebhook(10L).isPresent());
    }

    @Test
    void getWebhook_tenant없으면_404예외() {
        when(tenants.findById(99L)).thenReturn(Optional.empty());

        AuthException e = assertThrows(AuthException.class, () -> service.getWebhook(99L));
        assertEquals(AuthException.Kind.NOT_FOUND, e.getKind());
    }

    // --- enroll secret ---

    @Test
    void getEnrollSecret_미발급이면_그자리에서_발급한다() {
        // 사용자가 버튼을 눌러야 secret 이 생기면 설치 명령이 비어 보인다. tenant 당 하나면 되니 조회 시점에 만든다.
        Tenant tenant = newTenant();
        when(tenants.findById(1L)).thenReturn(Optional.of(tenant));

        String secret = service.getEnrollSecret(1L).orElseThrow();

        assertFalse(secret.isBlank());
        assertEquals(secret, tenant.getEnrollSecret());
        verify(tenants).save(tenant);
    }

    @Test
    void getEnrollSecret_이미있으면_그대로_돌려준다() {
        // 조회할 때마다 값이 바뀌면 이미 배포한 기기의 설치 안내가 어긋난다.
        Tenant tenant = newTenant();
        tenant.updateEnrollSecret("fixed-secret");
        when(tenants.findById(1L)).thenReturn(Optional.of(tenant));

        assertEquals("fixed-secret", service.getEnrollSecret(1L).orElseThrow());
        assertEquals("fixed-secret", service.getEnrollSecret(1L).orElseThrow());
    }

    @Test
    void getEnrollSecret_tenant없으면_404예외() {
        when(tenants.findById(9L)).thenReturn(Optional.empty());

        AuthException e = assertThrows(AuthException.class, () -> service.getEnrollSecret(9L));
        assertEquals(AuthException.Kind.NOT_FOUND, e.getKind());
    }
}
