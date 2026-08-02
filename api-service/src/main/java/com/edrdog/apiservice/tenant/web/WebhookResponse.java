package com.edrdog.apiservice.tenant.web;

/** webhookUrl 은 미설정 시 null. */
public record WebhookResponse(Long tenantId, String webhookUrl) {
}
