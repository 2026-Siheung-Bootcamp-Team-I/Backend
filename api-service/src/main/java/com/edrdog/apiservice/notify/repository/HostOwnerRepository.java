package com.edrdog.apiservice.notify.repository;

import com.edrdog.apiservice.notify.domain.HostOwner;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface HostOwnerRepository extends JpaRepository<HostOwner, Long> {

    Optional<HostOwner> findByTenantIdAndHost(Long tenantId, String host);

    List<HostOwner> findByUserId(Long userId);
}
