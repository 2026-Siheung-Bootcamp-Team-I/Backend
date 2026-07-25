package com.edrdog.apiservice.auth.repository;

import com.edrdog.apiservice.auth.domain.UserSession;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SessionRepository extends JpaRepository<UserSession, String> {
}
