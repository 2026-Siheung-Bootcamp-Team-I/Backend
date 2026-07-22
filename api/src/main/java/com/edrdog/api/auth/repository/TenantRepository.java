package com.edrdog.api.auth.repository;

import com.edrdog.api.auth.domain.Tenant;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TenantRepository extends JpaRepository<Tenant, Long> {
}
