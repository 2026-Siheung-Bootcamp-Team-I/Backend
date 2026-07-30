package com.edrdog.apiservice.install;

import com.edrdog.apiservice.auth.exception.AuthException;
import com.edrdog.apiservice.auth.service.AuthService;
import com.edrdog.apiservice.auth.service.Principal;
import com.edrdog.apiservice.tenant.TenantService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Map;

/**
 * 설치 링크. 대시보드가 한 줄짜리 명령을 만들고, 엔드포인트가 그 링크로 설치 스크립트를 받는다.
 *
 * <p>이게 있는 이유는 설치하는 사람이 키를 다루지 않게 하기 위해서다. 전에는 enroll secret 을
 * 복사해 명령에 붙여야 했는데, 그건 우리가 편하려고 미룬 것이지 정상이 아니다. 키를 사람 손에
 * 쥐여 주면 채팅방에 붙고 스크린샷에 남는다.
 *
 * <p>{@code /i/**} 는 인증 없이 연다. 토큰 자체가 인증이다. 그래서 토큰을 짧게 살린다.
 */
@RestController
@Tag(name = "install", description = "설치 링크 발급과 설치 스크립트 배포")
public class InstallController {

    private static final String BEARER_PREFIX = "Bearer ";

    private final AuthService auth;
    private final TenantService tenants;
    private final InstallService install;
    private final InstallScripts scripts;
    private final String agentServer;
    private final String downloadBase;

    public InstallController(AuthService auth,
                             TenantService tenants,
                             InstallService install,
                             InstallScripts scripts,
                             @Value("${edrdog.install.agent-server:}") String agentServer,
                             @Value("${edrdog.install.download-base:}") String downloadBase) {
        this.auth = auth;
        this.tenants = tenants;
        this.install = install;
        this.scripts = scripts;
        this.agentServer = agentServer;
        this.downloadBase = downloadBase;
    }

    @Operation(summary = "설치 링크 발급",
            description = "로그인 유저(Bearer)의 tenant 로 짧게 사는 설치 토큰을 만들고, 붙여넣을 한 줄 명령까지 돌려준다.")
    @PostMapping("/api/tenant/install-link")
    public InstallLinkResponse issue(@RequestHeader(name = "Authorization", required = false) String authorization) {
        Principal principal = auth.resolve(bearerToken(authorization));
        InstallToken token = install.issue(principal.tenantId(), Instant.now());

        String base = requireConfigured(publicBase(), "edrdog.install.public-base");
        String link = base + "/i/" + token.getToken();
        return new InstallLinkResponse(
                token.getToken(),
                token.getExpiresAt(),
                "curl -fsSL " + link + " | sudo bash",
                "irm " + link + ".ps1 | iex");
    }

    @Operation(summary = "macOS 설치 스크립트", description = "설치 토큰으로 받는다. 인증 헤더가 필요 없다.")
    @GetMapping(value = "/i/{token}", produces = "text/x-shellscript; charset=utf-8")
    public ResponseEntity<String> macos(@PathVariable String token) {
        return script(scripts.macos(), token);
    }

    @Operation(summary = "Windows 설치 스크립트", description = "설치 토큰으로 받는다. 인증 헤더가 필요 없다.")
    @GetMapping(value = "/i/{token}.ps1", produces = MediaType.TEXT_PLAIN_VALUE + "; charset=utf-8")
    public ResponseEntity<String> windows(@PathVariable String token) {
        return script(scripts.windows(), token);
    }

    private ResponseEntity<String> script(String template, String token) {
        Long tenantId = install.resolve(token, Instant.now());
        String secret = tenants.getEnrollSecret(tenantId)
                .orElseThrow(() -> AuthException.notFound("tenant 의 enroll secret 이 없습니다"));

        String body = InstallScript.render(template, Map.of(
                "SERVER", requireConfigured(agentServer, "edrdog.install.agent-server"),
                "ENROLL_SECRET", secret,
                "DOWNLOAD_BASE", requireConfigured(downloadBase, "edrdog.install.download-base")));

        // 중간에 끼는 캐시가 이 응답을 들고 있으면 만료된 토큰의 스크립트가 계속 나간다.
        return ResponseEntity.ok()
                .header("Cache-Control", "no-store")
                .body(body);
    }

    /** 대시보드에 보여줄 링크의 앞부분. */
    private String publicBase() {
        return scripts.publicBase();
    }

    private static String requireConfigured(String value, String key) {
        if (value == null || value.isBlank()) {
            // 빈 값을 그대로 스크립트에 넣으면 엔드포인트에서야 깨진다. 여기서 막는다.
            throw AuthException.invalidInput(key + " 가 설정되지 않았습니다");
        }
        return value;
    }

    private static String bearerToken(String authorization) {
        if (authorization == null || !authorization.startsWith(BEARER_PREFIX)) {
            throw AuthException.unauthorized("인증이 필요합니다");
        }
        return authorization.substring(BEARER_PREFIX.length());
    }
}
