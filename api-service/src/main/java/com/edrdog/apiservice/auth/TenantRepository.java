package com.edrdog.apiservice.auth;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface TenantRepository extends JpaRepository<Tenant, Long> {

    /** enroll secret 으로 테넌트를 되찾는다(에이전트 enroll 검증). */
    Optional<Tenant> findByEnrollSecret(String enrollSecret);
}
