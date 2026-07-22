package com.edrdog.api.auth.repository;

import com.edrdog.api.auth.domain.AppUser;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * UserRepository 슬라이스(H2). findByEmail/existsByEmail 동작 확인.
 */
@DataJpaTest
class UserRepositoryTest {

    @Autowired
    private UserRepository users;

    @Test
    void findByEmail_와_existsByEmail() {
        users.save(AppUser.of("a@b.com", "hash", 1L, "admin", Instant.now()));

        assertTrue(users.findByEmail("a@b.com").isPresent());
        assertTrue(users.existsByEmail("a@b.com"));
        assertFalse(users.findByEmail("none@b.com").isPresent());
        assertFalse(users.existsByEmail("none@b.com"));
    }
}
