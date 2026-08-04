package com.edrdog.schema;

/**
 * Event.type 에 실리는 값. 에이전트가 보내는 문자열과 같아야 한다.
 * proto 의 enum 으로 두지 않은 이유는 에이전트와 ClickHouse 가 모두 이 값을 문자열로 다루기 때문이다.
 */
public final class EventTypes {

    public static final String PROCESS = "process";
    public static final String NETWORK = "network";
    public static final String FILE = "file";
    public static final String SCRIPT = "script";
    public static final String DNS = "dns";
    public static final String L7 = "l7";

    private EventTypes() {
    }

    public static boolean isKnown(String type) {
        return PROCESS.equals(type)
                || NETWORK.equals(type)
                || FILE.equals(type)
                || SCRIPT.equals(type)
                || DNS.equals(type)
                || L7.equals(type);
    }
}
