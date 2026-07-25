package com.edrdog.apiservice.notify.web;

/** 개인 webhook 등록 요청 본문. */
public record UserWebhookRequest(String webhookUrl) {
}
