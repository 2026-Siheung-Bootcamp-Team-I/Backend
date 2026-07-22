package com.edrdog.apiservice.auth.repository;

import com.edrdog.apiservice.auth.domain.Tenant;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TenantRepository extends JpaRepository<Tenant, Long> {
}
