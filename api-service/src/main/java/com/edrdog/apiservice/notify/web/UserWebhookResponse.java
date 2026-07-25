package com.edrdog.apiservice.notify.web;

/** 개인 webhook 조회/등록 응답. webhookUrl 은 미설정 시 null. */
public record UserWebhookResponse(Long userId, String webhookUrl) {
}
