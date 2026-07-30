package com.edrdog.apiservice.install;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * InstallScript: 설치 스크립트 템플릿 치환(순수).
 *
 * <p>여기서 만든 문자열은 엔드포인트에서 root 로 실행된다. 값 하나가 잘못 들어가면 그 기기에서
 * 임의의 명령이 도는 것과 같으므로, 치환 규칙을 테스트로 못 박는다.
 */
class InstallScriptTest {

    @Test
    void 자리표시자를_값으로_바꾼다() {
        String out = InstallScript.render("서버는 {{SERVER}} 다", Map.of("SERVER", "edr.example.com:8443"));

        assertEquals("서버는 edr.example.com:8443 다", out);
    }

    @Test
    void 같은_자리표시자가_여러_번_나와도_전부_바꾼다() {
        String out = InstallScript.render("{{A}}-{{A}}", Map.of("A", "x"));

        assertEquals("x-x", out);
    }

    @Test
    void 안_채운_자리표시자가_남으면_던진다() {
        // 그대로 내보내면 엔드포인트에서 "{{SERVER}}" 라는 호스트에 붙으려다 죽는다.
        // 그 시점엔 이미 바이너리가 깔린 뒤라 원인을 찾기 어렵다. 내보내기 전에 막는다.
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> InstallScript.render("{{SERVER}} {{SECRET}}", Map.of("SERVER", "h:1")));

        assertTrue(e.getMessage().contains("SECRET"), e.getMessage());
    }

    @Test
    void 값이_자리표시자를_담고_있으면_거부한다() {
        // 값에 심은 {{...}} 가 두 번째 바퀴에서 살아나 다른 값으로 바뀌는 걸 막아야 한다.
        // render 는 한 번만 훑어서 애초에 두 번째 바퀴가 없지만, 중괄호를 값에서 아예 막는
        // 쪽이 더 강한 보장이다. 나중에 누가 치환을 반복문으로 바꿔도 여기서 걸린다.
        assertThrows(IllegalArgumentException.class, () -> InstallScript.render("{{A}}", Map.of("A", "{{B}}")));
    }

    @Test
    void 셸에서_위험한_값은_거부한다() {
        // enroll secret 은 URL-safe base64 라 정상값은 여기 걸리지 않는다. 걸린다면 값이
        // 우리가 만든 것이 아니라는 뜻이고, 그건 스크립트 안에서 명령이 되기 전에 막아야 한다.
        for (String bad : new String[]{"a\"b", "a'b", "a b", "a$b", "a`b", "a;b", "a\nb", "a\\b", "a|b"}) {
            assertThrows(IllegalArgumentException.class,
                    () -> InstallScript.render("{{A}}", Map.of("A", bad)), "거부해야 한다: " + bad);
        }
    }

    @Test
    void 정상적인_값들은_통과한다() {
        // 실제로 들어가는 모양들이다. host:port, URL, URL-safe base64 토큰.
        for (String ok : new String[]{
                "edr.example.com:8443",
                "https://github.com/org/repo/releases/latest/download",
                "Zm9vYmFy-_09",
                "192.168.0.15:30443",
        }) {
            assertEquals(ok, InstallScript.render("{{A}}", Map.of("A", ok)));
        }
    }

    @Test
    void 빈_값은_거부한다() {
        // 빈 문자열이 들어가면 "--server" 뒤가 비어 인자 하나가 통째로 밀린다.
        assertThrows(IllegalArgumentException.class, () -> InstallScript.render("{{A}}", Map.of("A", "")));
    }
}
