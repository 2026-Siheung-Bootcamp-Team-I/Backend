package com.edrdog.apiservice.intelligence.correlate;

import com.google.common.net.InetAddresses;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Name;
import org.xbill.DNS.PTRRecord;
import org.xbill.DNS.Record;
import org.xbill.DNS.ReverseMap;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Type;

import java.net.InetAddress;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * dnsjava 로 실제 DNS 서버에 묻는 구현.
 * 이 조회는 화면 하나를 그리는 요청 안에서 동기로 일어난다. 타임아웃을 늘리면 응답 없는 서버 하나에
 * 요청 전체가 잡혀 관측 데이터까지 늦게 나온다.
 * 어떤 실패도 예외로 새어 나가지 않는다. 조회 실패와 "그런 이름이 없다"는 다른 사실이라 둘 다 상태로 담는다.
 */
@Component
public class DnsjavaResolver implements DnsResolver {

    private static final Logger log = LoggerFactory.getLogger(DnsjavaResolver.class);

    private final SimpleResolver resolver;

    public DnsjavaResolver(@Value("${edrdog.intelligence.dns-timeout-ms:2000}") long timeoutMs) {
        SimpleResolver r = null;
        try {
            r = new SimpleResolver();
            r.setTimeout(Duration.ofMillis(timeoutMs));
        } catch (Exception e) {
            // 여기서 던지면 DNS 설정이 없는 환경에서 기동 자체가 막힌다. 관측 데이터 조회는 DNS 와 무관하다.
            log.warn("DNS 리졸버를 만들지 못했다. 실시간 조회는 FAILED 로 응답한다: {}", e.toString());
        }
        this.resolver = r;
    }

    @Override
    public ForwardLookup forward(String domain) {
        if (resolver == null) {
            return ForwardLookup.failed("DNS 리졸버가 설정되지 않았다");
        }
        try {
            Set<String> addresses = new LinkedHashSet<>();
            // A 와 AAAA 는 별개 질의다. 하나만 보면 IPv6 로만 서비스하는 도메인을 놓친다.
            boolean answered = collect(domain, Type.A, addresses);
            boolean answeredV6 = collect(domain, Type.AAAA, addresses);

            if (!addresses.isEmpty()) {
                return ForwardLookup.ok(List.copyOf(addresses));
            }
            // 둘 다 "질의는 됐는데 답이 없다"면 없는 것이 맞다. 하나라도 못 물었으면 모른다고 해야 한다.
            return answered && answeredV6 ? ForwardLookup.notFound() : ForwardLookup.failed("DNS 조회에 실패했다");
        } catch (Exception e) {
            return ForwardLookup.failed(e.toString());
        }
    }

    @Override
    public ReverseLookup reverse(String ip) {
        if (resolver == null) {
            return ReverseLookup.failed("DNS 리졸버가 설정되지 않았다");
        }
        try {
            InetAddress address = InetAddresses.forString(ip);
            Name name = ReverseMap.fromAddress(address);
            Lookup lookup = newLookup(name.toString(), Type.PTR);
            Record[] records = lookup.run();

            if (lookup.getResult() == Lookup.SUCCESSFUL && records != null) {
                List<String> names = new ArrayList<>();
                for (Record record : records) {
                    if (record instanceof PTRRecord ptr) {
                        // 후행 점을 떼어 관측 도메인 표기와 같은 모양으로 준다.
                        names.add(trimRoot(ptr.getTarget().toString()));
                    }
                }
                if (!names.isEmpty()) {
                    return ReverseLookup.ok(names);
                }
            }
            return isNotFound(lookup.getResult()) ? ReverseLookup.notFound() : ReverseLookup.failed(lookup.getErrorString());
        } catch (Exception e) {
            return ReverseLookup.failed(e.toString());
        }
    }

    /** 질의 한 번. 서버가 답을 준 경우(없다는 답 포함) true, 아예 못 물었으면 false. */
    private boolean collect(String domain, int type, Set<String> out) throws Exception {
        Lookup lookup = newLookup(domain, type);
        Record[] records = lookup.run();
        if (records != null) {
            for (Record record : records) {
                if (record instanceof ARecord a) {
                    out.add(a.getAddress().getHostAddress());
                } else if (record instanceof AAAARecord aaaa) {
                    // 에이전트가 적재하는 IPv6 표기(축약형)와 맞춘다. 안 맞으면 관측 IP 와 다른 노드가 된다.
                    out.add(InetAddresses.toAddrString(aaaa.getAddress()));
                }
            }
        }
        return lookup.getResult() == Lookup.SUCCESSFUL || isNotFound(lookup.getResult());
    }

    private Lookup newLookup(String name, int type) throws Exception {
        Lookup lookup = new Lookup(name, type);
        lookup.setResolver(resolver);
        return lookup;
    }

    /** 서버가 "그런 이름/레코드 없다"고 답한 경우. 못 물어본 것과 구분해야 한다. */
    private static boolean isNotFound(int result) {
        return result == Lookup.HOST_NOT_FOUND || result == Lookup.TYPE_NOT_FOUND;
    }

    private static String trimRoot(String name) {
        return name.endsWith(".") ? name.substring(0, name.length() - 1) : name;
    }
}
