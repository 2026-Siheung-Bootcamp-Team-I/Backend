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
import org.springframework.web.client.RestClientException;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * 유저 개인 알림 설정: 개인 Slack webhook 등록/조회, 소유 host 등록/조회/해제,
 * 그리고 탐지 알림의 라우팅 대상(host 소유자의 목적지) 해결.
 * 검증 실패 400 / 없음 404 / 소유 충돌 409 / 외부 연동 실패 502 는 AuthException 으로 던져 전역 핸들러가 매핑한다.
 */
@Service
public class UserNotifyService {

    private static final String TEST_MESSAGE =
            "EDRDOG 테스트 알림입니다. 이 메시지가 보이면 webhook 연동이 정상입니다.";

    private final UserRepository users;
    private final HostOwnerRepository hostOwners;
    private final SlackWebhookClient slackWebhookClient;

    public UserNotifyService(UserRepository users, HostOwnerRepository hostOwners,
                              SlackWebhookClient slackWebhookClient) {
        this.users = users;
        this.hostOwners = hostOwners;
        this.slackWebhookClient = slackWebhookClient;
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
     * 저장된 개인 webhook 으로 테스트 메시지를 실제로 보내 도달 여부를 확인한다.
     * webhook 미등록 404, Slack 이 4xx/5xx 를 주거나 연결 자체가 실패하면 502.
     * 성공 시 Slack 이 준 HTTP 상태코드를 그대로 돌려준다.
     */
    @Transactional(readOnly = true)
    public int sendTestWebhook(Long userId) {
        String url = getWebhook(userId)
                .orElseThrow(() -> AuthException.notFound("등록된 webhook 이 없습니다"));
        int status;
        try {
            status = slackWebhookClient.send(url, TEST_MESSAGE);
        } catch (RestClientException e) {
            throw AuthException.upstreamError("Slack 연결에 실패했습니다: " + e.getMessage());
        }
        if (status < 200 || status >= 300) {
            throw AuthException.upstreamError("Slack 이 오류를 반환했습니다 (status=" + status + ")");
        }
        return status;
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
