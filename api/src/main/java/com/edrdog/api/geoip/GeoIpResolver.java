package com.edrdog.api.geoip;

import com.maxmind.geoip2.DatabaseReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.InputStream;
import java.net.InetAddress;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * GeoLite2-Country mmdb 로 IP -> ISO2 국가 코드를 해석한다.
 * 로드 우선순위: (1) db-path(env GEOIP_DB_PATH) 파일 -> (2) 클래스패스 번들(빌드 시 다운로드된 mmdb).
 * 둘 다 없으면 "비활성"으로 두고(경고 1회) 기동은 막지 않는다.
 * 조회는 ConcurrentHashMap 에 캐시해 같은 IP 의 반복 mmdb 조회를 피한다.
 * mmdb 접근을 이 클래스 뒤에 가둬, 집계 로직(GeoAggregator)은 스텁 resolver 로 테스트한다.
 */
@Component
public class GeoIpResolver {

    private static final Logger log = LoggerFactory.getLogger(GeoIpResolver.class);

    /** 빌드 시 downloadGeoLite2 태스크가 build/geoip 에 받아 jar 에 번들하는 파일명(클래스패스 루트). */
    private static final String CLASSPATH_DB = "GeoLite2-Country.mmdb";

    private final DatabaseReader reader;
    private final ConcurrentHashMap<String, Optional<String>> cache = new ConcurrentHashMap<>();

    public GeoIpResolver(@Value("${edrdog.geoip.db-path:}") String dbPath) {
        this.reader = load(dbPath);
    }

    private static DatabaseReader load(String dbPath) {
        // (1) 외부 경로 우선: 운영에서 GEOIP_DB_PATH 로 번들 mmdb 를 덮어쓸 수 있다.
        if (dbPath != null && !dbPath.isBlank()) {
            File f = new File(dbPath.trim());
            if (f.isFile()) {
                try {
                    DatabaseReader r = new DatabaseReader.Builder(f).build();
                    log.info("GeoIP DB 로드(파일): {}", dbPath);
                    return r;
                } catch (Exception e) {
                    log.warn("GeoIP DB 파일 로드 실패: {}. 클래스패스 번들 시도.", dbPath, e);
                }
            } else {
                log.warn("GeoIP DB 파일 없음: {}. 클래스패스 번들 시도.", dbPath);
            }
        }
        // (2) 클래스패스 번들: 빌드 시 다운로드된 mmdb(build/geoip -> jar).
        try (InputStream in = GeoIpResolver.class.getResourceAsStream("/" + CLASSPATH_DB)) {
            if (in != null) {
                DatabaseReader r = new DatabaseReader.Builder(in).build();
                log.info("GeoIP DB 로드(클래스패스): {}", CLASSPATH_DB);
                return r;
            }
        } catch (Exception e) {
            log.warn("GeoIP DB 클래스패스 로드 실패.", e);
        }
        log.warn("GeoIP DB 사용 불가(외부 경로·클래스패스 모두 없음). geo 조회 비활성(빈 배열 반환).");
        return null;
    }

    /** mmdb 가 로드됐는지. false 면 컨트롤러는 빈 배열(200)을 준다. */
    public boolean isAvailable() {
        return reader != null;
    }

    /** IP 의 ISO2 국가 코드. 비활성/사설/미해석이면 empty. 결과는 캐시된다. */
    public Optional<String> countryCode(String ip) {
        if (reader == null || !PrivateIp.isPublic(ip)) {
            return Optional.empty();
        }
        return cache.computeIfAbsent(ip.trim(), this::lookup);
    }

    private Optional<String> lookup(String ip) {
        try {
            InetAddress addr = InetAddress.getByName(ip);
            return reader.tryCountry(addr)
                    .map(r -> r.getCountry())
                    .map(c -> c.getIsoCode())
                    .filter(code -> code != null && !code.isBlank());
        } catch (Exception e) {
            return Optional.empty();
        }
    }
}
