package com.edrdog.apiservice.osquery.web;

import com.edrdog.apiservice.osquery.OsqueryService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

/**
 * osquery TLS remote API 3종(enroll/config/log). 프론트 X-API-Key 가 아니라 자체 node_key/enroll_secret 으로
 * 인증하므로 ApiKeyFilter 예외 경로다. 인증 실패는 osquery 규약대로 {@code node_invalid:true} 로 응답한다.
 */
@RestController
@RequestMapping("/api/osquery")
@Tag(name = "osquery", description = "osquery 엔드포인트 수집 API (enroll/config/log)")
public class OsqueryController {

    private final OsqueryService service;
    private final ObjectMapper mapper = new ObjectMapper();

    public OsqueryController(OsqueryService service) {
        this.service = service;
    }

    @Operation(summary = "enroll", description = "enroll_secret(테넌트) 검증 후 node_key 를 발급한다. 실패 시 node_invalid:true.")
    @PostMapping("/enroll")
    public ObjectNode enroll(@RequestBody EnrollRequest req) {
        Optional<String> nodeKey = service.enroll(req.enrollSecret(), req.hostIdentifier(), req.platformType());
        ObjectNode res = mapper.createObjectNode();
        nodeKey.ifPresent(key -> res.put("node_key", key));
        res.put("node_invalid", nodeKey.isEmpty());
        return res;
    }

    @Operation(summary = "config", description = "node_key 인증 후 수집 쿼리(osquery.conf schedule)를 응답한다. 실패 시 node_invalid:true.")
    @PostMapping("/config")
    public JsonNode config(@RequestBody NodeKeyRequest req) {
        Optional<String> config = service.config(req.nodeKey());
        if (config.isEmpty()) {
            return invalid();
        }
        try {
            ObjectNode res = (ObjectNode) mapper.readTree(config.get());
            res.put("node_invalid", false);
            return res;
        } catch (Exception e) {
            throw new IllegalStateException("osquery 설정 직렬화 실패", e);
        }
    }

    @Operation(summary = "log", description = "node_key 인증 후 result-log 를 tenant 태깅해 events-raw 로 발행한다. 실패 시 node_invalid:true.")
    @PostMapping("/log")
    public ObjectNode log(@RequestBody LogRequest req) {
        // result 만 발행 대상. status 등은 node_key 인증만 하고 발행하지 않는다(data=null).
        boolean valid = service.log(req.nodeKey(), req.isResult() ? req.data() : null);
        ObjectNode res = mapper.createObjectNode();
        res.put("node_invalid", !valid);
        return res;
    }

    private ObjectNode invalid() {
        ObjectNode res = mapper.createObjectNode();
        res.put("node_invalid", true);
        return res;
    }
}
