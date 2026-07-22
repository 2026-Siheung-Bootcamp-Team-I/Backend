package com.edrdog.api.auth;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 이메일/비밀번호 검증 규칙(순수).
 */
class AuthValidationTest {

    @Test
    void 이메일은_at_과_점을_모두_포함해야_유효() {
        assertTrue(AuthValidation.validEmail("a@b.com"));
        assertFalse(AuthValidation.validEmail("ab.com"));
        assertFalse(AuthValidation.validEmail("a@bcom"));
        assertFalse(AuthValidation.validEmail(null));
    }

    @Test
    void 비밀번호는_8자_이상이어야_유효() {
        assertTrue(AuthValidation.validPassword("12345678"));
        assertFalse(AuthValidation.validPassword("1234567"));
        assertFalse(AuthValidation.validPassword(null));
    }
}
