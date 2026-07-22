package com.edrdog.api.auth;

import com.edrdog.api.auth.domain.AppUser;
import com.edrdog.api.auth.domain.Tenant;
import com.edrdog.api.auth.domain.UserSession;
import com.edrdog.api.auth.repository.SessionRepository;
import com.edrdog.api.auth.repository.TenantRepository;
import com.edrdog.api.auth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * AuthService: 리포지토리는 목킹, BCrypt/AuthValidation 은 실제로 사용.
 */
class AuthServiceTest {

    private UserRepository users;
    private TenantRepository tenants;
    private SessionRepository sessions;
    private BCryptPasswordEncoder encoder;
    private AuthService service;

    @BeforeEach
    void setUp() {
        users = mock(UserRepository.class);
        tenants = mock(TenantRepository.class);
        sessions = mock(SessionRepository.class);
        encoder = new BCryptPasswordEncoder();
        service = new AuthService(users, tenants, sessions, encoder, 168L);
    }

    private static Tenant tenantWithId(long id) {
        Tenant t = Tenant.of("org", Instant.now());
        ReflectionTestUtils.setField(t, "id", id);
        return t;
    }

    private static AppUser userWithId(long id, String email, String hash) {
        AppUser u = AppUser.of(email, hash, 10L, "admin", Instant.now());
        ReflectionTestUtils.setField(u, "id", id);
        return u;
    }

    @Test
    void 회원가입시_tenant와_user가_생성되고_토큰이_반환된다() {
        when(users.existsByEmail("a@b.com")).thenReturn(false);
        when(tenants.save(any(Tenant.class))).thenReturn(tenantWithId(10L));
        when(users.save(any(AppUser.class))).thenReturn(userWithId(1L, "a@b.com", "hash"));

        AuthResult r = service.signup("a@b.com", "password1", "MyOrg");

        assertNotNull(r.token());
        assertEquals(1L, r.userId());
        assertEquals(10L, r.tenantId());
        assertEquals("admin", r.role());
        verify(tenants).save(any(Tenant.class));
        verify(users).save(any(AppUser.class));
        verify(sessions).save(any(UserSession.class));
    }

    @Test
    void 중복_이메일이면_예외() {
        when(users.existsByEmail("a@b.com")).thenReturn(true);

        AuthException e = assertThrows(AuthException.class,
                () -> service.signup("a@b.com", "password1", null));
        assertEquals(AuthException.Kind.DUPLICATE, e.getKind());
    }

    @Test
    void 로그인_성공시_토큰_반환() {
        String hash = encoder.encode("password1");
        when(users.findByEmail("a@b.com")).thenReturn(Optional.of(userWithId(1L, "a@b.com", hash)));

        AuthResult r = service.login("a@b.com", "password1");

        assertNotNull(r.token());
        assertEquals(1L, r.userId());
    }

    @Test
    void 잘못된_비밀번호면_401예외() {
        String hash = encoder.encode("password1");
        when(users.findByEmail("a@b.com")).thenReturn(Optional.of(userWithId(1L, "a@b.com", hash)));

        AuthException e = assertThrows(AuthException.class,
                () -> service.login("a@b.com", "wrongpass"));
        assertEquals(AuthException.Kind.UNAUTHORIZED, e.getKind());
    }

    @Test
    void 로그아웃후_resolve_실패() {
        service.logout("tok");
        verify(sessions).deleteById("tok");

        when(sessions.findById("tok")).thenReturn(Optional.empty());
        AuthException e = assertThrows(AuthException.class, () -> service.resolve("tok"));
        assertEquals(AuthException.Kind.UNAUTHORIZED, e.getKind());
    }

    @Test
    void 만료된_세션_resolve_실패() {
        UserSession expired = UserSession.of("tok", 1L, 10L, Instant.now().minusSeconds(60));
        when(sessions.findById("tok")).thenReturn(Optional.of(expired));

        AuthException e = assertThrows(AuthException.class, () -> service.resolve("tok"));
        assertEquals(AuthException.Kind.UNAUTHORIZED, e.getKind());
    }

    @Test
    void 유효한_세션_resolve_성공() {
        UserSession valid = UserSession.of("tok", 1L, 10L, Instant.now().plusSeconds(3600));
        when(sessions.findById("tok")).thenReturn(Optional.of(valid));
        when(users.findById(1L)).thenReturn(Optional.of(userWithId(1L, "a@b.com", "hash")));

        Principal p = service.resolve("tok");
        assertEquals(1L, p.userId());
        assertEquals("a@b.com", p.email());
    }
}
