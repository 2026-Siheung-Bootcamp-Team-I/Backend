package com.edrdog.api.auth.repository;

import com.edrdog.api.auth.domain.UserSession;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SessionRepository extends JpaRepository<UserSession, String> {
}
