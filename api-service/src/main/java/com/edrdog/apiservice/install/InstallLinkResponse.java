package com.edrdog.apiservice.install;

import java.time.Instant;

/**
 * 설치 링크 발급 응답.
 *
 * <p>명령줄을 서버가 만들어서 준다. 대시보드가 문자열을 조립하게 두면 서버 주소나 경로가
 * 바뀔 때마다 프론트도 같이 고쳐야 하고, 둘이 어긋나면 사용자가 붙여넣은 명령이 조용히
 * 틀린 곳을 가리킨다.
 */
public record InstallLinkResponse(
        String token,
        Instant expiresAt,
        String macosCommand,
        String windowsCommand) {
}
