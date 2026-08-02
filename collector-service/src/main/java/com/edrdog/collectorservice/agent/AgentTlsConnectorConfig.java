package com.edrdog.collectorservice.agent;

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
 * 에이전트 전용 HTTPS 커넥터(8443)를 기본 HTTP 커넥터(8082) 옆에 병설한다.
 * 엔드포인트가 보내는 이벤트는 평문으로 흘릴 값이 아니라 수집 경로에는 HTTPS 가 필수다.
 * {@code edrdog.agent.tls.enabled=true} 일 때만 활성. mTLS 는 쓰지 않고 node_key 로 인증한다.
 */
@Configuration
@ConditionalOnProperty(name = "edrdog.agent.tls.enabled", havingValue = "true")
@EnableConfigurationProperties(AgentTlsProperties.class)
public class AgentTlsConnectorConfig {

    @Bean
    public WebServerFactoryCustomizer<TomcatServletWebServerFactory> agentHttpsConnector(AgentTlsProperties props) {
        return factory -> factory.addAdditionalTomcatConnectors(build(props));
    }

    private Connector build(AgentTlsProperties props) {
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

    private String resolve(String location) {
        try {
            Resource resource = location.startsWith("classpath:")
                    ? new ClassPathResource(location.substring("classpath:".length()))
                    : new FileSystemResource(location);
            return resource.getFile().getAbsolutePath();
        } catch (Exception e) {
            throw new IllegalStateException("에이전트 TLS 키스토어를 찾을 수 없습니다: " + location
                    + " (scripts/gen-dev-keystore.sh 로 생성하세요)", e);
        }
    }
}
