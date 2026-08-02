package com.edrdog.apiservice.web;

import com.edrdog.apiservice.auth.exception.AuthException;
import com.edrdog.apiservice.auth.exception.AuthExceptionHandler;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 예외 → 상태코드·본문 매핑 계약.
 *
 * <p>여기서 봐야 하는 건 두 가지다. 하나는 컨트롤러가 정한 상태코드가 그대로 나가면서 본문만
 * {"error": 메시지} 로 통일되는가, 다른 하나는 {@link IllegalArgumentException} 이 400 으로
 * 바뀌지 않는가다. 후자는 "서버 버그를 클라이언트 잘못으로 보고하지 않는다" 는 결정을 못 박는 것이라
 * 이 테스트가 깨지면 매핑이 아니라 그 결정이 바뀐 것이다.
 */
class ApiExceptionHandlerTest {

    // 실제 앱처럼 advice 두 개를 함께 올린다. 하나만 올리면 둘이 겹칠 때 무슨 일이 나는지 못 본다.
    private final MockMvc mvc = MockMvcBuilders.standaloneSetup(new TestController())
            .setControllerAdvice(new ApiExceptionHandler(), new AuthExceptionHandler())
            .build();

    @Test
    void ResponseStatusException_은_자기_상태코드로_나가고_본문은_error_하나다() throws Exception {
        mvc.perform(get("/rse"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("잘못된 값입니다"));
    }

    @Test
    void 상태코드는_400_말고도_그대로_보존한다() throws Exception {
        // 데모 API 의 403 처럼 400 이 아닌 것도 있다. 전부 400 으로 뭉개면 화면이 원인을 못 가린다.
        mvc.perform(get("/rse-forbidden"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("권한이 없습니다"));
    }

    @Test
    void 사유가_없으면_상태_문구로_채운다() throws Exception {
        // 없는 경로 404 처럼 사유가 빈 예외가 있다. 예외 메시지로 채우면 내부 경로가 그대로 나간다.
        mvc.perform(get("/rse-noreason"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("Not Found"));
    }

    @Test
    void 필수_파라미터가_없으면_400_이고_어느_파라미터인지_알려준다() throws Exception {
        mvc.perform(get("/param").param("ts", "1"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("필수 파라미터가 없습니다: host"));
    }

    @Test
    void 파라미터_타입이_안_맞으면_400() throws Exception {
        mvc.perform(get("/param").param("host", "hostA").param("ts", "abc"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("파라미터 형식이 올바르지 않습니다: ts"));
    }

    @Test
    void AuthException_은_여전히_AuthExceptionHandler_가_받는다() throws Exception {
        // 이 advice 가 상위 타입을 잡기 시작하면 여기부터 깨진다. 401 이 400 이나 500 으로 바뀌면
        // 로그인 만료를 화면이 재로그인으로 안 읽는다.
        mvc.perform(get("/auth"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("토큰이 유효하지 않습니다"));
    }

    @Test
    void IllegalArgumentException_은_400_으로_바꾸지_않는다() throws Exception {
        // TenantScope 처럼 컨트롤러 검증을 지나쳐 터진 것은 서버 버그다. 400 으로 내보내면
        // 서버 잘못이 클라이언트 잘못으로 기록되고 500 알람에서도 사라진다.
        Exception e = assertThrows(Exception.class, () -> mvc.perform(get("/iae")));
        assertInstanceOf(IllegalArgumentException.class, e.getCause());
    }

    @RestController
    static class TestController {

        @GetMapping("/rse")
        String rse() {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "잘못된 값입니다");
        }

        @GetMapping("/rse-forbidden")
        String forbidden() {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "권한이 없습니다");
        }

        @GetMapping("/rse-noreason")
        String noReason() {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }

        @GetMapping("/param")
        String param(@RequestParam String host, @RequestParam Long ts) {
            return host + ts;
        }

        @GetMapping("/auth")
        String auth() {
            throw AuthException.unauthorized("토큰이 유효하지 않습니다");
        }

        @GetMapping("/iae")
        String iae() {
            throw new IllegalArgumentException("tenant 는 필수입니다(격리)");
        }
    }
}
