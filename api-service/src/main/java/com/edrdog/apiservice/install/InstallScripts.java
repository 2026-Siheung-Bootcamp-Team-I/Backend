package com.edrdog.apiservice.install;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * 설치 스크립트 원본(macos.sh / windows.ps1)을 읽어 들고 있는다.
 *
 * <p>부팅할 때 한 번 읽는다. 요청마다 읽으면 파일이 사라져도 누가 설치에 실패한 뒤에야 안다.
 *
 * <p>여기 담긴 템플릿은 InstallScript 의 치환을 거쳐 셸에서 실행된다. 자리표시자 이름이
 * 치환 규칙과 어긋나면 컴파일도 테스트도 지나가고 엔드포인트에서야 설치가 깨진다
 * (InstallScriptTest 가 치환 규칙을, InstallTemplatesTest 가 원본과의 정합을 따로 보는 이유).
 */
@Component
public class InstallScripts {

    private final String macos;
    private final String windows;
    private final String publicBase;

    public InstallScripts(@Value("${edrdog.install.public-base:}") String publicBase) {
        this.macos = read("install/macos.sh");
        this.windows = read("install/windows.ps1");
        this.publicBase = publicBase;
    }

    public String macos() {
        return macos;
    }

    public String windows() {
        return windows;
    }

    public String publicBase() {
        return publicBase;
    }

    private static String read(String path) {
        ClassPathResource resource = new ClassPathResource(path);
        try (InputStream in = resource.getInputStream()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("설치 스크립트를 읽지 못했다: " + path, e);
        }
    }
}
