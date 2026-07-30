package com.edrdog.apiservice.security;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

/**
 * Swagger 를 가리는 Basic 인증 판단(순수).
 *
 * <p>브라우저로 여는 화면이라 X-API-Key 를 붙일 수가 없어서(ApiKeyPolicy 가 예외로 둔 이유)
 * 브라우저가 스스로 붙일 수 있는 Basic 만 본다.
 */
public class SwaggerAuthPolicy {

    private static final List<String> PROTECTED_PREFIXES = List.of(
            "/swagger-ui",
            "/v3/api-docs"
    );

    private static final String SCHEME = "basic ";

    private final String user;
    private final String password;

    public SwaggerAuthPolicy(String user, String password) {
        this.user = user;
        this.password = password;
    }

    public boolean isProtected(String path) {
        return PROTECTED_PREFIXES.stream().anyMatch(path::startsWith);
    }

    /** 미설정이면 인증을 요구해도 답할 값이 없다. 그때 팝업을 띄우면 브라우저가 무한히 되묻는다. */
    public boolean isConfigured() {
        return password != null && !password.isEmpty();
    }

    /** 비번이 없으면 열어 두지 않고 전부 막는다. 열린 채로 두면 알아채기 어렵다. */
    public boolean isAuthorized(String authorizationHeader) {
        if (!isConfigured()) {
            return false;
        }
        if (authorizationHeader == null || !authorizationHeader.toLowerCase().startsWith(SCHEME)) {
            return false;
        }
        String decoded;
        try {
            decoded = new String(
                    Base64.getDecoder().decode(authorizationHeader.substring(SCHEME.length()).trim()),
                    StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return false;
        }
        // 비번에 콜론이 들어갈 수 있어 첫 콜론에서만 자른다(RFC 7617).
        int sep = decoded.indexOf(':');
        if (sep < 0) {
            return false;
        }
        return user.equals(decoded.substring(0, sep)) && password.equals(decoded.substring(sep + 1));
    }
}
