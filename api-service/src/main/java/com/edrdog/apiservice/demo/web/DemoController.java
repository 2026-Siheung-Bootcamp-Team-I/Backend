package com.edrdog.apiservice.demo.web;

import com.edrdog.apiservice.demo.DemoAccountSeeder;
import com.edrdog.apiservice.demo.DemoFlowService;
import com.edrdog.apiservice.demo.DemoScenario;
import com.edrdog.apiservice.demo.DemoTenant;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * 발표용 전체 플로우 시연 REST. 인증 없이 실제 파이프라인을 그대로 태운다.
 *
 * <p>인증을 받지 않는 대신 할 수 있는 일을 좁혀 뒀다. 데모 계정의 tenant({@link DemoTenant})에만 쓰고
 * 미리 정해진 시나리오 4종만 발행한다. 둘 중 하나라도 풀면 인증 없이 남의 조직에 쓰는 경로가 열린다.
 */
@RestController
@RequestMapping("/api/demo")
@Tag(name = "demo", description = "발표용 전체 플로우 시연 (데모 조직 전용, 인증 없이 클릭 한 번)")
public class DemoController {

    private final DemoFlowService flow;
    private final DemoTenant demoTenant;

    public DemoController(DemoFlowService flow, DemoTenant demoTenant) {
        this.flow = flow;
        this.demoTenant = demoTenant;
    }

    @Operation(summary = "엔드포인트 로그 수집 시연 (전체 플로우)",
            description = "선택한 공격 시나리오의 로그를 엔드포인트가 보낸 것처럼 events 토픽으로 발행하고, "
                    + "detector Kafka Streams 가 판정을 alerts 토픽으로 되돌려 저장되기까지 기다린 뒤 "
                    + "단계별 소요시간과 결과를 한 번에 돌려준다. 평소 돌고 있던 정상 프로세스 로그도 함께 실려 "
                    + "실제 수집처럼 보인다. 결과는 데모 계정으로 로그인한 대시보드에 그대로 나타난다.\n\n"
                    + "- process-chain: 매크로 문서가 shell 실행 (T1059, HIGH)\n"
                    + "- download-exec: 외부 다운로드 후 그 파일 실행 (T1105+T1204, CRITICAL)\n"
                    + "- script-exec: 다운로드 경로 스크립트 실행 (T1059, MEDIUM)\n"
                    + "- file-autorun: 시작프로그램 경로에 파일 생성 (T1547, MEDIUM)\n\n"
                    + "host 를 비워두면 시나리오별 기본 호스트를 쓴다. 시나리오마다 기본 호스트를 다르게 둔 "
                    + "이유는 detector 상관 버퍼가 host 별 5분이라 같은 호스트로 여러 시나리오를 연달아 돌리면 "
                    + "의도한 룰이 아닌 다른 룰이 먼저 매칭될 수 있기 때문이다. "
                    + "판정까지 기다리므로 응답에 수 초가 걸린다.")
    @PostMapping("/collect/{scenario}")
    public DemoFlowResponse collect(
            @Parameter(description = "공격 시나리오",
                    schema = @Schema(allowableValues = {"process-chain", "download-exec", "script-exec", "file-autorun"}))
            @PathVariable String scenario,
            @Parameter(description = "엔드포인트 식별자. 비우면 시나리오 기본 호스트")
            @RequestParam(required = false) String host) {
        if (!DemoScenario.isSupported(scenario)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "미지원 시나리오: " + scenario + " (지원: " + String.join(", ", DemoScenario.names()) + ")");
        }
        String tenantId = demoTenant.resolve().orElseThrow(() -> new ResponseStatusException(
                HttpStatus.FORBIDDEN,
                "데모 계정(" + DemoAccountSeeder.EMAIL + ")이 없는 환경입니다. "
                        + "발표 환경에서 DEMO_SEED=true 로 시드를 켜야 이 API 가 동작합니다"));
        return flow.run(scenario, host, tenantId);
    }
}
