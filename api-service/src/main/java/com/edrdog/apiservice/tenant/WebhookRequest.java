package com.edrdog.apiservice.tenant;

/** webhook 등록 요청 본문. */
public record WebhookRequest(String webhookUrl) {
}
