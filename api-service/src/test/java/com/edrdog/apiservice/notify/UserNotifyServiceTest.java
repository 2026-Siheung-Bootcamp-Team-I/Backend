package com.edrdog.apiservice.notify;

import com.edrdog.apiservice.auth.domain.AppUser;
import com.edrdog.apiservice.auth.exception.AuthException;
import com.edrdog.apiservice.auth.repository.UserRepository;
import com.edrdog.apiservice.notify.domain.HostOwner;
import com.edrdog.apiservice.notify.repository.HostOwnerRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * UserNotifyService: 리포지토리는 목킹, WebhookValidation 은 실제 사용.
 */
class UserNotifyServiceTest {

    private UserRepository users;
    private HostOwnerRepository hostOwners;
    private UserNotifyService service;

    @BeforeEach
    void setUp() {
        users = mock(UserRepository.class);
        hostOwners = mock(HostOwnerRepository.class);
        service = new UserNotifyService(users, hostOwners);
    }

    private static AppUser newUser(Long tenantId) {
        return AppUser.of("u@e.com", "hash", tenantId, "admin", Instant.now());
    }

    // --- webhook ---

    @Test
    @DisplayName("setWebhook: 유효 URL 이면 유저에 저장")
    void setWebhook_valid_saves() {
        AppUser u = newUser(1L);
        when(users.findById(10L)).thenReturn(Optional.of(u));

        service.setWebhook(10L, "https://hooks.slack.com/services/x");

        assertEquals("https://hooks.slack.com/services/x", u.getSlackWebhookUrl());
        verify(users).save(any(AppUser.class));
    }

    @Test
    @DisplayName("setWebhook: https 아니면 400")
    void setWebhook_invalid_400() {
        AuthException e = assertThrows(AuthException.class, () -> service.setWebhook(10L, "http://no"));
        assertEquals(AuthException.Kind.INVALID_INPUT, e.getKind());
    }

    @Test
    @DisplayName("setWebhook: 유저 없으면 404")
    void setWebhook_noUser_404() {
        when(users.findById(99L)).thenReturn(Optional.empty());
        AuthException e = assertThrows(AuthException.class,
                () -> service.setWebhook(99L, "https://hooks.slack.com/x"));
        assertEquals(AuthException.Kind.NOT_FOUND, e.getKind());
    }

    @Test
    @DisplayName("getWebhook: 미설정이면 empty")
    void getWebhook_unset_empty() {
        when(users.findById(10L)).thenReturn(Optional.of(newUser(1L)));
        assertThat(service.getWebhook(10L)).isEmpty();
    }

    // --- host 등록 ---

    @Test
    @DisplayName("registerHost: 미소유 host 면 저장")
    void registerHost_new_saves() {
        when(hostOwners.findByTenantIdAndHost(1L, "host-1")).thenReturn(Optional.empty());

        service.registerHost(1L, 10L, "host-1");

        verify(hostOwners).save(any(HostOwner.class));
    }

    @Test
    @DisplayName("registerHost: 이미 내가 소유면 멱등(중복 저장 안 함)")
    void registerHost_alreadyMine_idempotent() {
        when(hostOwners.findByTenantIdAndHost(1L, "host-1"))
                .thenReturn(Optional.of(HostOwner.of(1L, "host-1", 10L, Instant.now())));

        service.registerHost(1L, 10L, "host-1");

        verify(hostOwners, never()).save(any(HostOwner.class));
    }

    @Test
    @DisplayName("registerHost: 다른 유저가 소유 중이면 409")
    void registerHost_ownedByOther_409() {
        when(hostOwners.findByTenantIdAndHost(1L, "host-1"))
                .thenReturn(Optional.of(HostOwner.of(1L, "host-1", 99L, Instant.now())));

        AuthException e = assertThrows(AuthException.class,
                () -> service.registerHost(1L, 10L, "host-1"));
        assertEquals(AuthException.Kind.DUPLICATE, e.getKind());
    }

    @Test
    @DisplayName("registerHost: find 통과 후 동시 insert 가 unique 제약을 밟으면 409")
    void registerHost_raceOnUnique_409() {
        when(hostOwners.findByTenantIdAndHost(1L, "host-1")).thenReturn(Optional.empty());
        when(hostOwners.save(any(HostOwner.class)))
                .thenThrow(new org.springframework.dao.DataIntegrityViolationException("dup"));

        AuthException e = assertThrows(AuthException.class,
                () -> service.registerHost(1L, 10L, "host-1"));
        assertEquals(AuthException.Kind.DUPLICATE, e.getKind());
    }

    @Test
    @DisplayName("registerHost: host 가 blank 면 400")
    void registerHost_blank_400() {
        AuthException e = assertThrows(AuthException.class,
                () -> service.registerHost(1L, 10L, "  "));
        assertEquals(AuthException.Kind.INVALID_INPUT, e.getKind());
    }

    @Test
    @DisplayName("listHosts: 내 host 목록 반환")
    void listHosts_returnsHosts() {
        when(hostOwners.findByUserId(10L)).thenReturn(List.of(
                HostOwner.of(1L, "host-a", 10L, Instant.now()),
                HostOwner.of(1L, "host-b", 10L, Instant.now())));

        assertThat(service.listHosts(10L)).containsExactly("host-a", "host-b");
    }

    @Test
    @DisplayName("unregisterHost: 내 host 면 삭제")
    void unregisterHost_mine_deletes() {
        HostOwner owned = HostOwner.of(1L, "host-1", 10L, Instant.now());
        when(hostOwners.findByTenantIdAndHost(1L, "host-1")).thenReturn(Optional.of(owned));

        service.unregisterHost(1L, 10L, "host-1");

        verify(hostOwners).delete(owned);
    }

    @Test
    @DisplayName("unregisterHost: 내 host 아니면 404")
    void unregisterHost_notMine_404() {
        when(hostOwners.findByTenantIdAndHost(1L, "host-1"))
                .thenReturn(Optional.of(HostOwner.of(1L, "host-1", 99L, Instant.now())));

        AuthException e = assertThrows(AuthException.class,
                () -> service.unregisterHost(1L, 10L, "host-1"));
        assertEquals(AuthException.Kind.NOT_FOUND, e.getKind());
    }

    // --- 라우팅 대상 해결 ---

    @Test
    @DisplayName("resolveTarget: 소유자 있고 webhook 있으면 (userId, webhook)")
    void resolveTarget_ownerWithWebhook() {
        when(hostOwners.findByTenantIdAndHost(1L, "host-1"))
                .thenReturn(Optional.of(HostOwner.of(1L, "host-1", 10L, Instant.now())));
        AppUser u = newUser(1L);
        u.updateWebhook("https://hooks/u");
        when(users.findById(10L)).thenReturn(Optional.of(u));

        Optional<AlertTarget> t = service.resolveTarget(1L, "host-1");

        assertThat(t).isPresent();
        assertEquals(10L, t.get().userId());
        assertEquals("https://hooks/u", t.get().webhookUrl());
    }

    @Test
    @DisplayName("resolveTarget: 소유자 없으면 empty (관리자 fallback 유도)")
    void resolveTarget_noOwner_empty() {
        when(hostOwners.findByTenantIdAndHost(1L, "host-x")).thenReturn(Optional.empty());
        assertThat(service.resolveTarget(1L, "host-x")).isEmpty();
    }

    @Test
    @DisplayName("resolveTarget: 소유자는 있으나 webhook 미설정이면 empty")
    void resolveTarget_ownerNoWebhook_empty() {
        when(hostOwners.findByTenantIdAndHost(1L, "host-1"))
                .thenReturn(Optional.of(HostOwner.of(1L, "host-1", 10L, Instant.now())));
        when(users.findById(10L)).thenReturn(Optional.of(newUser(1L)));

        assertThat(service.resolveTarget(1L, "host-1")).isEmpty();
    }
}
