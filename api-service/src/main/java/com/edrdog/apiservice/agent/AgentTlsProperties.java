package com.edrdog.apiservice.agent;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 에이전트 전용 HTTPS 커넥터 설정. dev 는 self-signed 키스토어 경로만 지정하면 된다.
 *
 * @param enabled          HTTPS 커넥터 활성 여부(기본 false, 켜면 keystore 필수)
 * @param port             HTTPS 리슨 포트(프론트 HTTP 와 별개)
 * @param keystore         키스토어 위치(파일 경로 또는 classpath:)
 * @param keystorePassword 키스토어 비밀번호
 * @param keystoreType     키스토어 타입(PKCS12)
 * @param keyAlias         키 alias(비우면 첫 키 사용)
 */
@ConfigurationProperties(prefix = "edrdog.agent.tls")
public record AgentTlsProperties(
        boolean enabled,
        int port,
        String keystore,
        String keystorePassword,
        String keystoreType,
        String keyAlias
) {
    public AgentTlsProperties {
        if (port == 0) {
            port = 8443;
        }
        if (keystoreType == null || keystoreType.isBlank()) {
            keystoreType = "PKCS12";
        }
    }
}
