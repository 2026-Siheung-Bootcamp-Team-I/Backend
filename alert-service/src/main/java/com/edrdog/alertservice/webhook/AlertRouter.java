package com.edrdog.alertservice.webhook;

import com.edrdog.alertservice.dto.Alert;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * 탐지 alert 를 어디로 보낼지 결정한다.
 * 1) host 소유 유저의 개인 webhook (per-user)
 * 2) 없으면 tenant webhook (관리자 채널 fallback)
 * 3) 둘 다 없으면 empty (발송 skip)
 * cooldownId 는 중복 억제 단위를 구분한다: 유저 경로는 {@code user:{userId}}, fallback 은 {@code tenant:{tenantId}}.
 */
@Component
public class AlertRouter {

    private final HostTargetClient hostTargets;
    private final TenantWebhookClient tenantWebhooks;

    public AlertRouter(HostTargetClient hostTargets, TenantWebhookClient tenantWebhooks) {
        this.hostTargets = hostTargets;
        this.tenantWebhooks = tenantWebhooks;
    }

    /** alert 의 발송 대상을 해결. 유저 목적지 우선, 없으면 tenant fallback, 그것도 없으면 empty. */
    public Optional<Route> route(Alert alert) {
        Optional<HostTargetClient.Target> target = hostTargets.resolve(alert.tenantId(), alert.host());
        if (target.isPresent()) {
            return Optional.of(new Route(target.get().webhookUrl(), "user:" + target.get().userId()));
        }
        return tenantWebhooks.resolve(alert.tenantId())
                .map(url -> new Route(url, "tenant:" + alert.tenantId()));
    }

    /** 발송 목적지 URL + 쿨다운 단위 식별자. */
    public record Route(String webhookUrl, String cooldownId) {
    }
}
