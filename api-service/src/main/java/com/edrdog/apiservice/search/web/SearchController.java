package com.edrdog.apiservice.search.web;

import com.edrdog.apiservice.auth.exception.AuthException;
import com.edrdog.apiservice.auth.service.AuthService;
import com.edrdog.apiservice.auth.service.Principal;
import com.edrdog.apiservice.search.SearchQueryBuilder;
import com.edrdog.apiservice.search.SearchService;
import com.edrdog.apiservice.search.SearchTerm;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 상단바 통합 검색 REST. 세션 Bearer 토큰으로 인증하고 그 tenant 로만 격리한다
 * (EventQueryController 와 동일 패턴).
 */
@RestController
@RequestMapping("/api")
@Tag(name = "search", description = "통합 검색 (알림·호스트·이벤트를 한 번에, tenant 격리)")
public class SearchController {

    private static final String BEARER_PREFIX = "Bearer ";

    /**
     * 기본 조회 기간: 최근 7일. 목록 조회의 24시간보다 넓게 잡는 이유는 검색이 "어디 있는지 모를 때"
     * 쓰는 것이라서다. 어제 본 것을 못 찾으면 상단바를 다시 안 쓴다.
     * 이벤트는 TTL 이 7일이라 이보다 넓혀도 나올 것이 없다.
     */
    private static final long DEFAULT_WINDOW_MS = 7 * 24 * 60 * 60 * 1000L;

    private final SearchService search;
    private final AuthService auth;

    public SearchController(SearchService search, AuthService auth) {
        this.search = search;
        this.auth = auth;
    }

    @Operation(summary = "통합 검색",
            description = "로그인 유저의 tenant 것만 알림·호스트·이벤트를 한 번에 훑어 종류별 상위 N건을 준다. "
                    + "대소문자를 가리지 않는 부분일치이며, %/_ 는 패턴이 아니라 찾을 글자다.\n\n"
                    + "검색 대상: 이벤트는 host/process/parent/cmdline/domain/dest_ip/sha256, "
                    + "알림은 id/host/rule_id/mitre/domain/dest_ip 와 화면에 보이는 한글 위협명, "
                    + "호스트는 이름이다.\n\n"
                    + "q 는 " + SearchTerm.MIN_LENGTH + ".." + SearchTerm.MAX_LENGTH + "글자여야 하고 "
                    + "벗어나면 400 이다(한 글자는 사실상 전부와 일치해 결과가 조사에 쓸모없다). "
                    + "limit 은 종류별 상한이며 기본 " + SearchQueryBuilder.DEFAULT_LIMIT
                    + ", 상한 " + SearchQueryBuilder.MAX_LIMIT + " 로 클램프한다.\n\n"
                    + "기간은 from/to(epoch millis)로 주고, 안 주면 최근 7일이다. 부분일치는 인덱스를 못 쓰므로 "
                    + "이 기간이 스캔 범위를 정한다. 실제로 적용된 값은 응답의 from/to 에 실려 나간다.\n\n"
                    + "**섹션마다 hasMore 가 붙는다.** 상한 때문에 잘렸다는 뜻이며, 전부 보려면 "
                    + "해당 목록 조회(/api/alerts, /api/hosts, /api/events)로 넘어가야 한다. "
                    + "호스트 섹션만 기간을 적용하지 않는다(조용한 기기가 기간 밖이라고 사라지면 안 된다).")
    @GetMapping("/search")
    public SearchResponse search(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @RequestParam(required = false) String q,
            @RequestParam(required = false) Long from,
            @RequestParam(required = false) Long to,
            @RequestParam(required = false) Integer limit) {
        String tenantId = currentTenantId(authorization);
        String term = requireTerm(q);
        long resolvedTo = to != null ? to : System.currentTimeMillis();
        long resolvedFrom = from != null ? from : resolvedTo - DEFAULT_WINDOW_MS;
        return search.search(tenantId, term, resolvedFrom, resolvedTo, limit);
    }

    /** 정규화는 순수 로직이라 IllegalArgumentException 을 던진다. 그대로 두면 500 이라 400 으로 옮긴다. */
    private static String requireTerm(String q) {
        try {
            return SearchTerm.normalize(q);
        } catch (IllegalArgumentException e) {
            throw AuthException.invalidInput(e.getMessage());
        }
    }

    private String currentTenantId(String authorization) {
        Principal principal = auth.resolve(bearerToken(authorization));
        return String.valueOf(principal.tenantId());
    }

    private static String bearerToken(String authorization) {
        if (authorization == null || !authorization.startsWith(BEARER_PREFIX)) {
            return null;
        }
        return authorization.substring(BEARER_PREFIX.length()).trim();
    }
}
