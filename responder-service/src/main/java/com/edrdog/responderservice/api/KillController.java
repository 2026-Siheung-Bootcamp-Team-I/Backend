package com.edrdog.responderservice.api;

import com.edrdog.responderservice.response.ExecuteResult;
import com.edrdog.responderservice.response.ResponseExecutor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 반자동 실제 조치 트리거 API. 대시보드의 "실행" 버튼이 호출한다(자동 실행 아님).
 * 실행 경로(권한·Fleet 호출·kill 검증)는 다 만들되 방아쇠는 사람이 당긴다.
 */
@RestController
@RequestMapping("/api/responder")
public class KillController {

    private final ResponseExecutor executor;

    public KillController(ResponseExecutor executor) {
        this.executor = executor;
    }

    /** host 의 target 프로세스 kill 실행. */
    @PostMapping("/kill")
    public ResponseEntity<ExecuteResult> kill(@RequestBody KillRequest req) {
        if (isBlank(req.host()) || isBlank(req.target())) {
            return ResponseEntity.badRequest().build();
        }
        return ResponseEntity.ok(executor.killProcess(req.host(), req.target()));
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    /** kill 트리거 요청 본문. */
    public record KillRequest(String host, String target) {
    }
}
