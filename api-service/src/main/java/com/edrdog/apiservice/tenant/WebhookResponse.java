package com.edrdog.apiservice.tenant;

/** webhook 조회/등록 응답. webhookUrl 은 미설정 시 null. */
public record WebhookResponse(Long tenantId, String webhookUrl) {
}
