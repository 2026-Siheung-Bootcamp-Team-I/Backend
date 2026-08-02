package com.edrdog.responderservice.api;

import com.edrdog.responderservice.command.Command;
import com.edrdog.responderservice.command.CommandQueue;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * 에이전트 명령 채널. 에이전트는 collector-service 만 알고, collector 가 이 경로로 프록시한다.
 *
 * <p>responder 는 클러스터 안에서만 열리고 앱 인증이 없다. 바깥 노출은 collector 가 node_key 를
 * 검증한 뒤 프록시하는 경로뿐이다(kill 은 api-service 가 세션 인증 뒤 프록시한다).
 */
@RestController
@RequestMapping("/api/responder/commands")
public class CommandController {

    private final CommandQueue commands;

    public CommandController(CommandQueue commands) {
        this.commands = commands;
    }

    /** 그 호스트의 대기 명령을 꺼낸다. 하트비트마다 호출된다. */
    @GetMapping
    public List<Command> pending(@RequestParam("host") String host) {
        return commands.drainFor(host);
    }

    /** 에이전트가 보고한 실행 결과. 대기 중인 kill 요청을 깨운다. */
    @PostMapping("/result")
    public ResponseEntity<Void> result(@RequestBody CommandResult body) {
        if (body.commandId() == null || body.commandId().isBlank()) {
            return ResponseEntity.badRequest().build();
        }
        commands.complete(body.commandId(), body.status(), body.message());
        return ResponseEntity.ok().build();
    }

    /** 결과 보고 본문. 프로토콜 문서의 command-result 와 같은 필드라 스네이크 표기를 그대로 받는다. */
    public record CommandResult(@JsonProperty("command_id") String commandId, String status, String message) {
    }
}
