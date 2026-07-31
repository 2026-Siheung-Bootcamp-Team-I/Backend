package com.edrdog.apiservice.tenant;

/**
 * Slack webhook URL 검증(순수). 해커톤 수준의 최소 규칙만 둔다.
 */
public final class WebhookValidation {

    private WebhookValidation() {
    }

    public static boolean valid(String url) {
        return url != null && !url.isBlank() && url.startsWith("https://");
    }
}
