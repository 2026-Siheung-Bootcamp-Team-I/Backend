package com.edrdog.collectorservice.agent;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 하트비트가 내려줄 수집 설정이 플랫폼별로 갈리는지 검증.
 * 감시 경로가 틀리면 에이전트가 엉뚱한 디렉터리를 보게 되고, 자동실행 지속성(T1547) 판정이 통째로 비게 된다.
 */
class SensorConfigTest {

    @Test
    void 센서는_플랫폼과_무관하게_전부_켠다() {
        for (String platform : new String[]{"darwin", "windows"}) {
            SensorConfig.Sensors sensors = SensorConfig.forPlatform(platform).sensors();

            assertTrue(sensors.process(), platform);
            assertTrue(sensors.network(), platform);
            assertTrue(sensors.file(), platform);
            assertTrue(sensors.dns(), platform);
        }
    }

    @Test
    void darwin_은_LaunchAgents_와_LaunchDaemons_를_감시한다() {
        var paths = SensorConfig.forPlatform("darwin").watchPaths();

        assertTrue(paths.contains("/Library/LaunchAgents"));
        assertTrue(paths.contains("/Library/LaunchDaemons"));
    }

    /** 사용자별 LaunchAgents 는 계정마다 다르므로 홈 확장은 그 기기의 에이전트가 한다. */
    @Test
    void darwin_은_사용자별_LaunchAgents_를_물결_표기로_내려준다() {
        assertTrue(SensorConfig.forPlatform("darwin").watchPaths().contains("~/Library/LaunchAgents"));
    }

    @Test
    void windows_는_시작프로그램_경로를_감시한다() {
        var paths = SensorConfig.forPlatform("windows").watchPaths();

        assertTrue(paths.contains("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp"));
        assertTrue(paths.contains("C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"));
    }

    @Test
    void windows_와_darwin_의_감시_경로는_섞이지_않는다() {
        assertFalse(SensorConfig.forPlatform("windows").watchPaths().contains("/Library/LaunchAgents"));
        assertFalse(SensorConfig.forPlatform("darwin").watchPaths().toString().contains("ProgramData"));
    }

    /**
     * platform 은 Go 의 runtime.GOOS 값이 그대로 온다. "darwin" 이 "win" 을 부분문자열로 포함하므로
     * "windows" 로 봐야 mac 이 Windows 경로를 받는 일이 없다.
     */
    @Test
    void darwin_은_windows_로_오판되지_않는다() {
        assertTrue(SensorConfig.forPlatform("darwin").watchPaths().contains("/Library/LaunchDaemons"));
    }

    @Test
    void 플랫폼_미상이면_darwin_설정으로_폴백한다() {
        assertTrue(SensorConfig.forPlatform(null).watchPaths().contains("/Library/LaunchAgents"));
        assertTrue(SensorConfig.forPlatform("").watchPaths().contains("/Library/LaunchAgents"));
    }

    @Test
    void flush_주기를_내려준다() {
        assertEquals(5, SensorConfig.forPlatform("darwin").flushIntervalSeconds());
    }
}
