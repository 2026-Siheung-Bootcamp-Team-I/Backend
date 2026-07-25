package com.edrdog.apiservice.osquery;

import org.apache.catalina.connector.Connector;
import org.apache.coyote.http11.Http11NioProtocol;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.apache.tomcat.util.net.SSLHostConfigCertificate.Type;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;

/**
 * osquery 전용 HTTPS 커넥터(8443)를 기본 HTTP 커넥터(8084) 옆에 병설한다.
 * osquery TLS logger 는 평문 HTTP 로 연결하지 않으므로 수집 경로에는 HTTPS 가 필수다.
 * 프론트는 기존 HTTP 를 그대로 쓰게 두려고 서비스 전체를 HTTPS 로 돌리지 않고 커넥터만 하나 더 연다.
 *
 * <p>{@code edrdog.osquery.tls.enabled=true} 일 때만 활성. dev 는 self-signed 키스토어를 만들어
 * (scripts/gen-dev-keystore.sh) 경로를 지정하고, osquery 는 그 서버 cert 를 {@code --tls_server_certs} 로 핀한다.
 * mTLS(클라 인증서)는 후순위라 여기서 다루지 않는다(node_key 로 인증).
 */
@Configuration
@ConditionalOnProperty(name = "edrdog.osquery.tls.enabled", havingValue = "true")
@EnableConfigurationProperties(OsqueryTlsProperties.class)
public class OsqueryTlsConnectorConfig {

    @Bean
    public WebServerFactoryCustomizer<TomcatServletWebServerFactory> osqueryHttpsConnector(OsqueryTlsProperties props) {
        return factory -> factory.addAdditionalTomcatConnectors(build(props));
    }

    private Connector build(OsqueryTlsProperties props) {
        Connector connector = new Connector("org.apache.coyote.http11.Http11NioProtocol");
        connector.setScheme("https");
        connector.setSecure(true);
        connector.setPort(props.port());

        Http11NioProtocol protocol = (Http11NioProtocol) connector.getProtocolHandler();
        protocol.setSSLEnabled(true);

        SSLHostConfig sslHostConfig = new SSLHostConfig();
        SSLHostConfigCertificate cert = new SSLHostConfigCertificate(sslHostConfig, Type.UNDEFINED);
        cert.setCertificateKeystoreFile(resolve(props.keystore()));
        cert.setCertificateKeystorePassword(props.keystorePassword());
        cert.setCertificateKeystoreType(props.keystoreType());
        if (props.keyAlias() != null && !props.keyAlias().isBlank()) {
            cert.setCertificateKeyAlias(props.keyAlias());
        }
        sslHostConfig.addCertificate(cert);
        connector.addSslHostConfig(sslHostConfig);
        return connector;
    }

    /** classpath: 접두어면 리소스로, 아니면 파일 경로로 해석한 절대경로를 돌려준다. */
    private String resolve(String location) {
        try {
            Resource resource = location.startsWith("classpath:")
                    ? new ClassPathResource(location.substring("classpath:".length()))
                    : new FileSystemResource(location);
            return resource.getFile().getAbsolutePath();
        } catch (Exception e) {
            throw new IllegalStateException("osquery TLS 키스토어를 찾을 수 없습니다: " + location
                    + " (scripts/gen-dev-keystore.sh 로 생성하세요)", e);
        }
    }
}
