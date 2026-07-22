package com.edrdog.api.auth.web;

import com.edrdog.api.auth.AuthResult;
import com.edrdog.api.auth.AuthService;
import com.edrdog.api.auth.Principal;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 이메일+비밀번호 기반 회원가입/로그인/로그아웃/내정보. 자체 세션 토큰(Bearer)을 사용한다.
 * 이 경로는 X-API-Key 예외(ApiKeyPolicy)라 토큰만으로 접근한다.
 */
@RestController
@RequestMapping("/api/auth")
@Tag(name = "auth", description = "회원가입/로그인/로그아웃 (세션 토큰)")
public class AuthController {

    private static final String BEARER_PREFIX = "Bearer ";

    private final AuthService auth;

    public AuthController(AuthService auth) {
        this.auth = auth;
    }

    @Operation(summary = "회원가입", description = "이메일/비밀번호(+선택 조직명)로 가입하고 세션 토큰을 발급한다.")
    @PostMapping("/signup")
    public ResponseEntity<AuthResponse> signup(@RequestBody SignupRequest req) {
        AuthResult r = auth.signup(req.email(), req.password(), req.orgName());
        return ResponseEntity.status(HttpStatus.CREATED).body(AuthResponse.from(r));
    }

    @Operation(summary = "로그인", description = "이메일/비밀번호로 로그인하고 세션 토큰을 발급한다.")
    @PostMapping("/login")
    public AuthResponse login(@RequestBody LoginRequest req) {
        return AuthResponse.from(auth.login(req.email(), req.password()));
    }

    @Operation(summary = "로그아웃", description = "현재 토큰의 세션을 삭제한다(멱등).")
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestHeader(name = "Authorization", required = false) String authorization) {
        auth.logout(bearerToken(authorization));
        return ResponseEntity.noContent().build();
    }

    @Operation(summary = "내 정보", description = "Bearer 토큰으로 현재 유저 정보를 조회한다.")
    @GetMapping("/me")
    public MeResponse me(@RequestHeader(name = "Authorization", required = false) String authorization) {
        Principal p = auth.resolve(bearerToken(authorization));
        return new MeResponse(p.userId(), p.tenantId(), p.email(), p.role());
    }

    /** "Bearer " 접두어를 떼서 토큰만 반환. 없으면 null. */
    private static String bearerToken(String authorization) {
        if (authorization == null || !authorization.startsWith(BEARER_PREFIX)) {
            return null;
        }
        return authorization.substring(BEARER_PREFIX.length()).trim();
    }
}
