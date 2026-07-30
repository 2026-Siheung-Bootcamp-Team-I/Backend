package com.edrdog.apiservice.install;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface InstallTokenRepository extends JpaRepository<InstallToken, Long> {

    /** 설치 링크의 토큰으로 되찾는다. 만료 판정은 서비스가 한다. */
    Optional<InstallToken> findByToken(String token);
}
