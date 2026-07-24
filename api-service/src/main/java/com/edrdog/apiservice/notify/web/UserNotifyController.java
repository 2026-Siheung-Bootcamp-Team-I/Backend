package com.edrdog.apiservice.notify.web;

import com.edrdog.apiservice.auth.exception.AuthException;
import com.edrdog.apiservice.auth.service.AuthService;
import com.edrdog.apiservice.auth.service.Principal;
import com.edrdog.apiservice.notify.AlertTarget;
import com.edrdog.apiservice.notify.UserNotifyService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 유저 개인 알림 설정. host 소유 유저에게 개별로 탐지 알림을 보내기 위한 관리 API.
 * /api/me/** 은 로그인 유저(Bearer)가 자기 것만 다룬다.
 * /api/internal/alert-target 은 alert-service 가 host 소유자 목적지를 조회하는 서비스 간 경로(X-Internal-Key).
 */
@RestController
@Tag(name = "me", description = "유저 개인 알림 목적지·host 소유 등록")
public class UserNotifyController {

    private static final String BEARER_PREFIX = "Bearer ";

    private final UserNotifyService notify;
    private final AuthService auth;
    private final String internalKey;

    public UserNotifyController(UserNotifyService notify, AuthService auth,
                               @Value("${edrdog.internal.key}") String internalKey) {
        this.notify = notify;
        this.auth = auth;
        this.internalKey = internalKey;
    }

    @Operation(summary = "내 webhook 등록", description = "로그인 유저의 개인 Slack webhook URL 을 저장한다.")
    @PutMapping("/api/me/webhook")
    public UserWebhookResponse setWebhook(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @RequestBody UserWebhookRequest req) {
        Principal p = principal(authorization);
        notify.setWebhook(p.userId(), req.webhookUrl());
        return new UserWebhookResponse(p.userId(), req.webhookUrl());
    }

    @Operation(summary = "내 webhook 조회", description = "로그인 유저의 개인 Slack webhook URL 을 조회한다. 미설정이면 null.")
    @GetMapping("/api/me/webhook")
    public UserWebhookResponse getWebhook(
            @RequestHeader(name = "Authorization", required = false) String authorization) {
        Principal p = principal(authorization);
        return new UserWebhookResponse(p.userId(), notify.getWebhook(p.userId()).orElse(null));
    }

    @Operation(summary = "내 host 등록", description = "로그인 유저가 소유한 host 를 등록한다. 그 host 탐지 알림이 내 webhook 으로 온다.")
    @PostMapping("/api/me/hosts")
    public ResponseEntity<HostsResponse> registerHost(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @RequestBody HostRequest req) {
        Principal p = principal(authorization);
        notify.registerHost(p.tenantId(), p.userId(), req.host());
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new HostsResponse(notify.listHosts(p.userId())));
    }

    @Operation(summary = "내 host 목록", description = "로그인 유저가 소유 등록한 host 목록을 조회한다.")
    @GetMapping("/api/me/hosts")
    public HostsResponse listHosts(
            @RequestHeader(name = "Authorization", required = false) String authorization) {
        Principal p = principal(authorization);
        return new HostsResponse(notify.listHosts(p.userId()));
    }

    @Operation(summary = "내 host 해제", description = "로그인 유저가 소유 등록한 host 를 해제한다.")
    @DeleteMapping("/api/me/hosts/{host}")
    public ResponseEntity<Void> unregisterHost(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @PathVariable String host) {
        Principal p = principal(authorization);
        notify.unregisterHost(p.tenantId(), p.userId(), host);
        return ResponseEntity.noContent().build();
    }

    @Operation(summary = "내부 라우팅 대상 조회",
            description = "서비스 간 조회용(X-Internal-Key). 지정 tenant+host 의 소유 유저 목적지를 조회한다. 소유자 없거나 미설정이면 404.")
    @GetMapping("/api/internal/alert-target")
    public AlertTarget getAlertTarget(
            @RequestParam Long tenantId,
            @RequestParam String host,
            @RequestHeader(name = "X-Internal-Key", required = false) String internalKeyHeader) {
        if (internalKeyHeader == null || !internalKey.equals(internalKeyHeader)) {
            throw AuthException.unauthorized("유효한 X-Internal-Key 가 필요합니다");
        }
        return notify.resolveTarget(tenantId, host)
                .orElseThrow(() -> AuthException.notFound("host 소유 목적지가 없습니다"));
    }

    private Principal principal(String authorization) {
        return auth.resolve(bearerToken(authorization));
    }

    /** "Bearer " 접두어를 떼서 토큰만 반환. 없으면 null. */
    private static String bearerToken(String authorization) {
        if (authorization == null || !authorization.startsWith(BEARER_PREFIX)) {
            return null;
        }
        return authorization.substring(BEARER_PREFIX.length()).trim();
    }
}
