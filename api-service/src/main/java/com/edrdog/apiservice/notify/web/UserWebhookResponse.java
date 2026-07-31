package com.edrdog.apiservice.notify.web;

/** webhookUrl 은 미설정 시 null. */
public record UserWebhookResponse(Long userId, String webhookUrl) {
}
