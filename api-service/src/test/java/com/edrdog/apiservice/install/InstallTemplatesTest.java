package com.edrdog.apiservice.install;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 실제로 배포되는 설치 스크립트 원본을 그대로 렌더링해 본다.
 *
 * <p>InstallScriptTest 가 치환 규칙을 보는 것과 달리, 여기서는 파일이 그 규칙과 맞는지를 본다.
 * 템플릿에 {@code {{SERVERR}}} 같은 오타가 하나 있으면 컴파일도 테스트도 다 지나가고,
 * 엔드포인트에서 설치가 깨진 뒤에야 드러난다.
 */
class InstallTemplatesTest {

    private static final Map<String, String> VALUES = Map.of(
            "SERVER", "edr.example.com:8443",
            "ENROLL_SECRET", "Zm9vYmFy-_09",
            "DOWNLOAD_BASE", "https://github.com/org/repo/releases/latest/download");

    private final InstallScripts scripts = new InstallScripts("https://edr.example.com");

    @Test
    void macOS_원본은_채울_수_있는_자리표시자만_쓴다() {
        String out = InstallScript.render(scripts.macos(), VALUES);

        assertNoPlaceholderLeft(out);
        assertTrue(out.contains("edr.example.com:8443"), "서버 주소가 안 들어갔다");
        assertTrue(out.contains("Zm9vYmFy-_09"), "enroll secret 이 안 들어갔다");
    }

    @Test
    void windows_원본은_채울_수_있는_자리표시자만_쓴다() {
        String out = InstallScript.render(scripts.windows(), VALUES);

        assertNoPlaceholderLeft(out);
        assertTrue(out.contains("edr.example.com:8443"), "서버 주소가 안 들어갔다");
        assertTrue(out.contains("Zm9vYmFy-_09"), "enroll secret 이 안 들어갔다");
    }

    @Test
    void 두_원본_모두_등록을_확인하고_끝낸다() {
        // 서비스나 데몬이 떠 있다는 것과 서버에 붙었다는 것은 다른 말이다. 둘 다 KeepAlive 라
        // 못 붙어도 계속 살아 있어서, 떠 있는 것만 보고 끝내면 아무것도 안 오는 채로 설치가 끝난다.
        assertTrue(scripts.macos().contains("등록 완료"), "macOS 원본이 등록 여부를 안 본다");
        assertTrue(scripts.windows().contains("등록 완료"), "windows 원본이 등록 여부를 안 본다");
    }

    @Test
    void macOS_원본은_터미널을_따로_읽는다() {
        // curl 로 받아 실행하면 stdin 은 스크립트 자신이다. 그냥 read 를 쓰면 권한 승인을
        // 기다리지 않고 스크립트 다음 줄을 답으로 먹고 지나간다.
        assertTrue(scripts.macos().contains("/dev/tty"), "권한 대기를 /dev/tty 로 읽어야 한다");
    }

    @Test
    void 두_원본_모두_받은_해시의_모양을_먼저_본다() {
        // .sha256 파일은 "<해시>  <파일명>" 이다. 처음에는 공백을 지우고 뒤에서 64자를
        // 잘랐는데, 그러면 파일명 끝을 해시로 읽는다. 실제 릴리스로 받아 보고서야 알았고
        // 그때까지 모든 설치가 해시 불일치로 막혀 있었다.
        //
        // 모양 검사를 먼저 두면 추출이 또 깨져도 "해시가 다르다" 가 아니라 "모양이 다르다"
        // 로 나온다. 릴리스 파일이 깨진 것과 바이너리가 바뀐 것은 대응이 전혀 다르다.
        assertTrue(scripts.macos().contains("[A-Fa-f0-9]{64}"), "macOS 원본이 해시 모양을 안 본다");
        assertTrue(scripts.windows().contains("[A-Fa-f0-9]{64}"), "windows 원본이 해시 모양을 안 본다");
    }

    private static void assertNoPlaceholderLeft(String out) {
        assertFalse(out.contains("{{"), "안 채운 자리표시자가 남았다: "
                + out.replaceAll("(?s).*?(\\{\\{[A-Z_]*}}).*", "$1"));
    }
}
