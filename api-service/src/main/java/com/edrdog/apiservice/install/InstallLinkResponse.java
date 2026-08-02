package com.edrdog.apiservice.install;

import java.time.Instant;

/** 설치 링크 발급 응답. 붙여넣을 명령줄까지 서버가 만들어서 준다. */
public record InstallLinkResponse(
        String token,
        Instant expiresAt,
        String macosCommand,
        String windowsCommand) {
}
