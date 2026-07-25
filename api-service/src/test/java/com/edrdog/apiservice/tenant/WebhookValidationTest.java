package com.edrdog.apiservice.tenant;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Slack webhook URL 검증 규칙(순수). 해커톤 수준의 최소 규칙만 둔다.
 */
class WebhookValidationTest {

    @Test
    void https로_시작하는_URL만_유효() {
        assertTrue(WebhookValidation.valid("https://hooks.slack.com/services/xxx"));
        assertFalse(WebhookValidation.valid("http://hooks.slack.com/services/xxx"));
        assertFalse(WebhookValidation.valid("hooks.slack.com"));
    }

    @Test
    void null_또는_blank는_무효() {
        assertFalse(WebhookValidation.valid(null));
        assertFalse(WebhookValidation.valid(""));
        assertFalse(WebhookValidation.valid("   "));
    }
}
