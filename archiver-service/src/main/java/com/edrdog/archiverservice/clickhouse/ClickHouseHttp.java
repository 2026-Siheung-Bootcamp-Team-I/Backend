package com.edrdog.archiverservice.clickhouse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.http.client.ClientHttpRequestFactoryBuilder;
import org.springframework.boot.http.client.ClientHttpRequestFactorySettings;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.time.Duration;

/** ClickHouse HTTP(8123) 접속 한 곳. 접속 정보와 타임아웃을 이 클래스만 알면 되게 모아 둔다. */
// 타임아웃이 없으면 ClickHouse 가 느려질 때 Kafka 컨슈머 스레드가 무한정 잡혀 적재가 통째로 멈춘다.
@Component
public class ClickHouseHttp {

    private final RestClient client;

    public ClickHouseHttp(
            @Value("${edrdog.clickhouse.url}") String url,
            @Value("${edrdog.clickhouse.database}") String database,
            @Value("${edrdog.clickhouse.user}") String user,
            @Value("${edrdog.clickhouse.password}") String password,
            @Value("${edrdog.clickhouse.connect-timeout-ms}") long connectTimeoutMs,
            @Value("${edrdog.clickhouse.read-timeout-ms}") long readTimeoutMs) {
        ClientHttpRequestFactorySettings timeouts = ClientHttpRequestFactorySettings.defaults()
                .withConnectTimeout(Duration.ofMillis(connectTimeoutMs))
                .withReadTimeout(Duration.ofMillis(readTimeoutMs));
        this.client = RestClient.builder()
                .baseUrl(url)
                .requestFactory(ClientHttpRequestFactoryBuilder.detect().build(timeouts))
                .defaultHeader("X-ClickHouse-User", user)
                .defaultHeader("X-ClickHouse-Key", password)
                .defaultHeader("X-ClickHouse-Database", database)
                .build();
    }

    /** 응답 본문이 필요 없는 문장(DDL, INSERT). */
    public void execute(String sql) {
        client.post()
                .uri("/")
                .contentType(MediaType.TEXT_PLAIN)
                .body(sql)
                .retrieve()
                .toBodilessEntity();
    }

    /** 응답 본문이 필요한 문장(SHOW CREATE 등). 본문이 없으면 빈 문자열. */
    public String query(String sql) {
        String body = client.post()
                .uri("/")
                .contentType(MediaType.TEXT_PLAIN)
                .body(sql)
                .retrieve()
                .body(String.class);
        return body == null ? "" : body;
    }
}
