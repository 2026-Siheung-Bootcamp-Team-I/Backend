package com.edrdog.api.auth;

import com.edrdog.api.auth.domain.AppUser;
import com.edrdog.api.auth.domain.Tenant;
import com.edrdog.api.auth.domain.UserSession;
import com.edrdog.api.auth.repository.SessionRepository;
import com.edrdog.api.auth.repository.TenantRepository;
import com.edrdog.api.auth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;

/**
 * 회원가입/로그인/로그아웃/토큰검증. 비밀번호는 BCrypt, 세션은 opaque 토큰 + DB 저장 방식.
 */
@Service
public class AuthService {

    private final UserRepository users;
    private final TenantRepository tenants;
    private final SessionRepository sessions;
    private final BCryptPasswordEncoder encoder;
    private final Duration sessionTtl;

    public AuthService(UserRepository users,
                       TenantRepository tenants,
                       SessionRepository sessions,
                       BCryptPasswordEncoder encoder,
                       @Value("${edrdog.auth.session-ttl-hours:168}") long sessionTtlHours) {
        this.users = users;
        this.tenants = tenants;
        this.sessions = sessions;
        this.encoder = encoder;
        this.sessionTtl = Duration.ofHours(sessionTtlHours);
    }

    /**
     * 조직·유저 생성 후 세션 발급. 이메일/비번 형식 오류 400, 중복 이메일 409.
     * 한 트랜잭션으로 묶어 중간 실패 시 tenant 까지 롤백(고아 데이터 방지).
     * existsByEmail 통과 후 동시 요청이 unique 제약을 밟으면 409 로 변환한다.
     */
    @Transactional
    public AuthResult signup(String email, String password, String orgName) {
        if (!AuthValidation.validEmail(email)) {
            throw AuthException.invalidInput("이메일 형식이 올바르지 않습니다");
        }
        if (!AuthValidation.validPassword(password)) {
            throw AuthException.invalidInput("비밀번호는 8자 이상이어야 합니다");
        }
        if (users.existsByEmail(email)) {
            throw AuthException.duplicate("이미 사용 중인 이메일입니다");
        }

        Instant now = Instant.now();
        String name = (orgName == null || orgName.isBlank()) ? localPart(email) : orgName;
        try {
            Tenant tenant = tenants.save(Tenant.of(name, now));
            AppUser user = users.save(AppUser.of(email, encoder.encode(password), tenant.getId(), "admin", now));
            return issueSession(user, now);
        } catch (DataIntegrityViolationException e) {
            throw AuthException.duplicate("이미 사용 중인 이메일입니다");
        }
    }

    /** 이메일/비번 확인 후 세션 발급. 자격증명 불일치 401. */
    public AuthResult login(String email, String password) {
        AppUser user = users.findByEmail(email)
                .filter(u -> encoder.matches(password, u.getPasswordHash()))
                .orElseThrow(() -> AuthException.unauthorized("이메일 또는 비밀번호가 올바르지 않습니다"));
        return issueSession(user, Instant.now());
    }

    /** 세션 삭제. 없어도 조용히 성공(멱등). */
    public void logout(String token) {
        if (token != null) {
            sessions.deleteById(token);
        }
    }

    /** 토큰으로 현재 유저 확인. 없거나 만료면 401. */
    public Principal resolve(String token) {
        UserSession session = (token == null ? null : sessions.findById(token).orElse(null));
        if (session == null || session.isExpired(Instant.now())) {
            throw AuthException.unauthorized("유효하지 않거나 만료된 토큰입니다");
        }
        AppUser user = users.findById(session.getUserId())
                .orElseThrow(() -> AuthException.unauthorized("유효하지 않은 토큰입니다"));
        return new Principal(user.getId(), user.getTenantId(), user.getEmail(), user.getRole());
    }

    private AuthResult issueSession(AppUser user, Instant now) {
        UserSession session = UserSession.of(
                Tokens.newToken(), user.getId(), user.getTenantId(), now.plus(sessionTtl));
        sessions.save(session);
        return new AuthResult(session.getToken(), user.getId(), user.getTenantId(), user.getEmail(), user.getRole());
    }

    private static String localPart(String email) {
        return email.substring(0, email.indexOf('@'));
    }
}
