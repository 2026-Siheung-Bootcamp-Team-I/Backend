package com.edrdog.apiservice.notify;

import com.edrdog.apiservice.auth.domain.AppUser;
import com.edrdog.apiservice.auth.exception.AuthException;
import com.edrdog.apiservice.auth.repository.UserRepository;
import com.edrdog.apiservice.notify.domain.HostOwner;
import com.edrdog.apiservice.notify.repository.HostOwnerRepository;
import com.edrdog.apiservice.tenant.WebhookValidation;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * 유저 개인 알림 설정: 개인 Slack webhook 등록/조회, 소유 host 등록/조회/해제,
 * 그리고 탐지 알림의 라우팅 대상(host 소유자의 목적지) 해결.
 * 검증 실패 400 / 없음 404 / 소유 충돌 409 는 AuthException 으로 던져 전역 핸들러가 매핑한다.
 */
@Service
public class UserNotifyService {

    private final UserRepository users;
    private final HostOwnerRepository hostOwners;

    public UserNotifyService(UserRepository users, HostOwnerRepository hostOwners) {
        this.users = users;
        this.hostOwners = hostOwners;
    }

    /** 개인 webhook 등록/갱신. URL 검증 실패 400, 유저 없음 404. */
    @Transactional
    public void setWebhook(Long userId, String url) {
        if (!WebhookValidation.valid(url)) {
            throw AuthException.invalidInput("webhook URL 은 https:// 로 시작해야 합니다");
        }
        AppUser user = user(userId);
        user.updateWebhook(url);
        users.save(user);
    }

    /** 개인 webhook 조회. 유저 없음 404, 미설정이면 빈 Optional. */
    @Transactional(readOnly = true)
    public Optional<String> getWebhook(Long userId) {
        return Optional.ofNullable(user(userId).getSlackWebhookUrl());
    }

    /**
     * 소유 host 등록. 이미 내가 소유면 멱등(no-op), 같은 tenant 안에서 다른 유저가 소유 중이면 409.
     * host blank 400.
     */
    @Transactional
    public void registerHost(Long tenantId, Long userId, String host) {
        if (host == null || host.isBlank()) {
            throw AuthException.invalidInput("host 는 비어 있을 수 없습니다");
        }
        Optional<HostOwner> existing = hostOwners.findByTenantIdAndHost(tenantId, host);
        if (existing.isPresent()) {
            if (!existing.get().getUserId().equals(userId)) {
                throw AuthException.duplicate("이미 다른 유저가 소유한 host 입니다");
            }
            return;   // 이미 내 것 → 멱등
        }
        try {
            hostOwners.save(HostOwner.of(tenantId, host, userId, Instant.now()));
        } catch (DataIntegrityViolationException e) {
            // find 통과 후 동시 요청이 unique(tenantId, host) 를 밟은 경우 → 409
            throw AuthException.duplicate("이미 다른 유저가 소유한 host 입니다");
        }
    }

    /** 내가 소유한 host 목록. */
    @Transactional(readOnly = true)
    public List<String> listHosts(Long userId) {
        return hostOwners.findByUserId(userId).stream()
                .map(HostOwner::getHost)
                .toList();
    }

    /** 소유 host 해제. 내 host 가 아니면(미등록 포함) 404. */
    @Transactional
    public void unregisterHost(Long tenantId, Long userId, String host) {
        HostOwner owner = hostOwners.findByTenantIdAndHost(tenantId, host)
                .filter(o -> o.getUserId().equals(userId))
                .orElseThrow(() -> AuthException.notFound("등록된 내 host 가 아닙니다"));
        hostOwners.delete(owner);
    }

    /**
     * 탐지 알림 라우팅 대상 해결: host 소유자의 개인 webhook.
     * 소유자 없거나 소유자가 webhook 미설정이면 empty(호출측이 관리자 채널로 fallback 하도록).
     */
    @Transactional(readOnly = true)
    public Optional<AlertTarget> resolveTarget(Long tenantId, String host) {
        return hostOwners.findByTenantIdAndHost(tenantId, host)
                .flatMap(owner -> users.findById(owner.getUserId())
                        .filter(u -> u.getSlackWebhookUrl() != null && !u.getSlackWebhookUrl().isBlank())
                        .map(u -> new AlertTarget(owner.getUserId(), u.getSlackWebhookUrl())));
    }

    private AppUser user(Long userId) {
        return users.findById(userId)
                .orElseThrow(() -> AuthException.notFound("유저를 찾을 수 없습니다"));
    }
}
