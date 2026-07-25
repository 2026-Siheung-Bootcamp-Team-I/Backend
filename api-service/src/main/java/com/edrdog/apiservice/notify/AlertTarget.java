package com.edrdog.apiservice.notify;

/**
 * host 소유 유저의 알림 목적지. resolveTarget 결과이자 내부 라우팅 엔드포인트 응답의 원본.
 */
public record AlertTarget(Long userId, String webhookUrl) {
}
