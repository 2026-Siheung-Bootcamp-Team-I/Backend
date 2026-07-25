package com.edrdog.alertservice.webhook;

import com.edrdog.alertservice.dto.Alert;
import com.edrdog.alertservice.webhook.AlertRouter.Route;
import com.edrdog.alertservice.webhook.HostTargetClient.Target;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** AlertRouter: 유저 목적지 우선 → tenant fallback → skip 라우팅 결정. */
class AlertRouterTest {

    private HostTargetClient hostTargets;
    private TenantWebhookClient tenantWebhooks;
    private AlertRouter router;

    @BeforeEach
    void setUp() {
        hostTargets = mock(HostTargetClient.class);
        tenantWebhooks = mock(TenantWebhookClient.class);
        router = new AlertRouter(hostTargets, tenantWebhooks);
    }

    private Alert alert() {
        return new Alert("7", "host-1", "RULE", "T1059", "HIGH", "kill", 1_000, List.of("e"));
    }

    @Test
    @DisplayName("host 소유 유저 목적지가 있으면 그 webhook + user 쿨다운 식별자")
    void route_userTarget() {
        when(hostTargets.resolve("7", "host-1")).thenReturn(Optional.of(new Target(10L, "https://hooks/u")));

        Optional<Route> route = router.route(alert());

        assertThat(route).contains(new Route("https://hooks/u", "user:10"));
    }

    @Test
    @DisplayName("유저 목적지 없으면 tenant webhook + tenant 쿨다운 식별자 (관리자 fallback)")
    void route_tenantFallback() {
        when(hostTargets.resolve("7", "host-1")).thenReturn(Optional.empty());
        when(tenantWebhooks.resolve("7")).thenReturn(Optional.of("https://hooks/admin"));

        Optional<Route> route = router.route(alert());

        assertThat(route).contains(new Route("https://hooks/admin", "tenant:7"));
    }

    @Test
    @DisplayName("유저·tenant 목적지 모두 없으면 empty (skip)")
    void route_none_empty() {
        when(hostTargets.resolve("7", "host-1")).thenReturn(Optional.empty());
        when(tenantWebhooks.resolve("7")).thenReturn(Optional.empty());

        assertThat(router.route(alert())).isEmpty();
    }

    @Test
    @DisplayName("유저 목적지가 있으면 tenant 조회는 하지 않는다")
    void route_userTarget_skipsTenantLookup() {
        when(hostTargets.resolve("7", "host-1")).thenReturn(Optional.of(new Target(10L, "https://hooks/u")));

        router.route(alert());

        org.mockito.Mockito.verifyNoInteractions(tenantWebhooks);
    }
}
