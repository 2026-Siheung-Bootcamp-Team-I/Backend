package com.edrdog.apiservice.auth;

import org.springframework.data.jpa.repository.JpaRepository;

public interface SessionRepository extends JpaRepository<UserSession, String> {
}
