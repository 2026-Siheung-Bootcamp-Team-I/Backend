package com.edrdog.apiservice.clickhouse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.http.client.ClientHttpRequestFactoryBuilder;
import org.springframework.boot.http.client.ClientHttpRequestFactorySettings;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.time.Duration;
import java.util.Map;

/** ClickHouse HTTP(8123) 접속 한 곳. 접속 정보와 타임아웃을 이 클래스만 알면 되게 모아 둔다. */
// 타임아웃이 없으면 ClickHouse 가 느려질 때 호출 스레드가 무한정 잡혀 API 전체가 같이 멎는다.
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

    /** 조회. 바인딩 값은 SQL 본문이 아니라 URL 의 param_* 로 나간다. */
    // 값을 본문에 이어붙이면 SQL 인젝션이 열린다.
    public String query(String sql, Map<String, String> params) {
        return client.post()
                .uri(uriBuilder -> {
                    uriBuilder.path("/");
                    params.forEach((k, v) -> uriBuilder.queryParam("param_" + k, v));
                    return uriBuilder.build();
                })
                .contentType(MediaType.TEXT_PLAIN)
                .body(sql)
                .retrieve()
                .body(String.class);
    }

    /** 응답 본문이 필요 없는 문장(INSERT 등). */
    public void execute(String sql) {
        client.post()
                .uri("/")
                .contentType(MediaType.TEXT_PLAIN)
                .body(sql)
                .retrieve()
                .toBodilessEntity();
    }
}
