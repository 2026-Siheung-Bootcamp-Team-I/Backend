package com.edrdog.alertservice;

import com.edrdog.alertservice.dto.Alert;
import com.edrdog.alertservice.slack.SlackNotifier;
import com.edrdog.alertservice.webhook.AlertRouter;
import com.edrdog.alertservice.webhook.AlertRouter.Route;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** AlertListener: 라우팅 결과에 따른 발송/skip 과 쿨다운 억제·롤백. */
class AlertListenerTest {

    private static final String WEBHOOK = "https://hooks/abc";

    private AlertRouter router;
    private SlackNotifier slack;
    private AlertListener listener;

    @BeforeEach
    void setUp() {
        router = mock(AlertRouter.class);
        slack = mock(SlackNotifier.class);
        listener = new AlertListener(60_000, router, slack);
    }

    private Alert alert(long ts) {
        return new Alert("t1", "host-1", "SUSPICIOUS_PROCESS_CHAIN", "T1059",
                Alert.SEV_HIGH, Alert.ACTION_KILL, ts, List.of("evidence"));
    }

    private void routed() {
        when(router.route(any())).thenReturn(Optional.of(new Route(WEBHOOK, "user:1")));
    }

    @Test
    @DisplayName("목적지가 있으면 그 webhook 으로 발송한다")
    void routed_sends() {
        routed();
        when(slack.send(any(), anyString())).thenReturn(true);

        listener.onAlert(alert(1_000));

        verify(slack).send(any(), anyString());
    }

    @Test
    @DisplayName("목적지가 없으면 발송하지 않는다")
    void noRoute_skips() {
        when(router.route(any())).thenReturn(Optional.empty());

        listener.onAlert(alert(1_000));

        verify(slack, never()).send(any(), anyString());
    }

    @Test
    @DisplayName("발송에 성공하면 윈도우 안 같은 alert 는 억제된다")
    void sendSucceeded_withinWindow_suppressed() {
        routed();
        when(slack.send(any(), anyString())).thenReturn(true);

        listener.onAlert(alert(1_000));
        listener.onAlert(alert(2_000));

        verify(slack, times(1)).send(any(), anyString());
    }

    @Test
    @DisplayName("발송에 실패하면 쿨다운을 롤백해 다음 alert 를 막지 않는다")
    void sendFailed_cooldownRolledBack() {
        routed();
        when(slack.send(any(), anyString())).thenReturn(false);

        listener.onAlert(alert(1_000));
        listener.onAlert(alert(2_000));

        verify(slack, times(2)).send(any(), anyString());
    }
}
