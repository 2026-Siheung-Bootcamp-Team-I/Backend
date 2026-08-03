// 도착 순서가 뒤바뀌어도 탐지 건수가 같은지 부하로 확인하는 k6 시나리오.
//
// 같은 공격 시퀀스(R2 다운로드 → 실행)를 같은 양으로 보내되 도착 순서만 바꾼다.
// 구간마다 그래프가 어떤 모양이어야 하는지 먼저 정하고, 그대로 나오는지 본다.
//
//   구간           방법                              기대 탐지  기대 late 카운터
//   inorder        발생 순서대로                     N          0
//   shuffled       실행이 먼저 도착                  N          0        <- 이 글의 주장
//   lateTrigger    트리거가 기준선 넘겨 도착         N          N        <- 버리지 않는다
//   lateEvidence   근거가 grace 넘겨 도착            0          0        <- 한계 지점
//
// 단말은 반복마다 새로 만든다. 단말을 공유하면 다른 반복이 남긴 근거로 판정돼 구간의 의미가 사라진다.
//
//   실행: k6 run scripts/loadtest/ordering.js
//   대상: detector 의 데모 발행 경로(POST /api/events). host 를 파티션 키로 events 토픽에 넣는다.

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter } from 'k6/metrics';

const BASE = __ENV.BASE_URL || 'http://localhost:8081';
const RATE = Number(__ENV.RATE || 20);          // 초당 시퀀스 수
const PHASE_S = Number(__ENV.PHASE_SECONDS || 60);
const GAP_S = Number(__ENV.GAP_SECONDS || 30);  // 구간 사이 공백 (그래프에서 단계를 가른다)
const NOISE = Number(__ENV.NOISE || 3);         // 시퀀스당 무해한 이벤트 수
const LATE_MS = Number(__ENV.LATE_MS || 2500);  // 근거를 늦추는 시간. grace(1500ms)보다 커야 미탐이 난다
const TENANT = __ENV.TENANT_ID || '1';

const sent = new Counter('edrdog_sequences_sent');

const phase = (name, order, exec) => ({
    executor: 'constant-arrival-rate',
    rate: RATE,
    timeUnit: '1s',
    duration: `${PHASE_S}s`,
    startTime: `${order * (PHASE_S + GAP_S)}s`,
    // lateEvidence 는 한 반복이 LATE_MS 만큼 머무르므로 VU 가 rate × LATE_MS 만큼 동시에 필요하다
    preAllocatedVUs: 80,
    maxVUs: 300,
    exec,
    tags: { phase: name },
});

export const options = {
    scenarios: {
        inorder: phase('inorder', 0, 'inOrder'),
        shuffled: phase('shuffled', 1, 'shuffled'),
        lateTrigger: phase('lateTrigger', 2, 'lateTrigger'),
        lateEvidence: phase('lateEvidence', 3, 'lateEvidence'),
    },
    // 발행이 막히면 결과를 믿을 수 없다. 실패가 보이면 바로 알도록 임계값을 건다.
    thresholds: {
        http_req_failed: ['rate<0.01'],
    },
};

function post(event) {
    const res = http.post(`${BASE}/api/events`, JSON.stringify(event), {
        headers: { 'Content-Type': 'application/json' },
    });
    check(res, { 'accepted': (r) => r.status === 202 });
}

/** 반복마다 새 단말. 반복끼리 근거를 빌려주지 않게 한다. */
function newHost(name) {
    return `h-${name}-${__VU}-${__ITER}`;
}

/** R2 의 선행 근거. 다운로드 포트여야 근거로 인정된다. */
function download(host, ts) {
    return { host, type: 'network', ts, destIp: '203.0.113.9', destPort: 443, tenantId: TENANT };
}

/** R2 의 트리거. argv[0] 이 시스템 임시 경로여야 한다. */
function execFromTemp(host, ts) {
    return {
        host, type: 'process', ts,
        process: 'payload.bin', parent: 'bash', cmdline: '/tmp/payload.bin',
        tenantId: TENANT,
    };
}

/** 룰에 안 걸리는 평범한 실행. 부하를 만들고 기준선을 밀어준다. */
function benign(host, ts) {
    return {
        host, type: 'process', ts,
        process: 'chrome.exe', parent: 'launchd',
        cmdline: '/applications/chrome.app/contents/macos/chrome',
        tenantId: TENANT,
    };
}

function noise(host, ts) {
    for (let i = 0; i < NOISE; i++) {
        post(benign(host, ts - i * 10));
    }
}

// 1) 발생 순서대로 도착. 기준값이 되는 구간이다
export function inOrder() {
    const host = newHost('inorder');
    const now = Date.now();
    post(download(host, now - 2000));
    post(execFromTemp(host, now));
    noise(host, now);
    sent.add(1, { phase: 'inorder' });
}

// 2) 실행이 먼저 도착하고 근거가 뒤따라온다. 발생 시각은 그대로다
export function shuffled() {
    const host = newHost('shuffled');
    const now = Date.now();
    post(execFromTemp(host, now));
    post(download(host, now - 2000));
    noise(host, now);
    sent.add(1, { phase: 'shuffled' });
}

// 3) 최신 이벤트가 기준선을 먼저 밀어버린 뒤 트리거가 도착한다.
//    버리면 확정 미탐이라 그 자리에서 판정한다. 탐지는 되고 late 카운터가 오르는 게 정상이다
export function lateTrigger() {
    const host = newHost('latetrigger');
    const now = Date.now();
    // 기준선을 미는 이벤트는 근거로 쌓이는 종류여야 한다. 무해한 이벤트로 밀면 버퍼가 비어
    // 그 자리에서 상태가 삭제되고(CorrelationProcessor.save) 기준선도 같이 초기화된다
    post(download(host, now));                 // 기준선을 now-1500 으로 민다
    post(download(host, now - 6000));          // 실제 근거
    post(execFromTemp(host, now - 4000));      // 기준선보다 과거 → late
    noise(host, now);
    sent.add(1, { phase: 'lateTrigger' });
}

// 4) 근거가 grace 를 넘겨 도착한다. 트리거가 이미 판정된 뒤라 미탐이 정상이다
export function lateEvidence() {
    const host = newHost('lateevidence');
    const now = Date.now();
    post(execFromTemp(host, now));
    noise(host, now);
    sleep(LATE_MS / 1000);
    post(download(host, now - 2000));
    sent.add(1, { phase: 'lateEvidence' });
}

export function handleSummary(data) {
    const total = data.metrics.edrdog_sequences_sent?.values?.count ?? 0;
    const n = Math.round(RATE * PHASE_S);
    const lines = [
        '',
        `보낸 시퀀스 합계 ${total} (구간당 ${n} = rate ${RATE}/s × ${PHASE_S}s)`,
        '',
        '구간별 기대 모양 — 그라파나가 이대로 나와야 한다',
        '',
        `  inorder        탐지 ${n}    late 0`,
        `  shuffled       탐지 ${n}    late 0      <- inorder 와 같아야 주장이 성립한다`,
        `  lateTrigger    탐지 ${n}    late ${n}    <- 늦게 온 트리거도 버리지 않는다`,
        `  lateEvidence   탐지 0${' '.repeat(String(n).length - 1)}    late 0      <- grace 를 넘긴 근거는 못 살린다`,
        '',
    ];
    return {
        stdout: lines.join('\n'),
        'scripts/loadtest/result-ordering.json': JSON.stringify(data, null, 2),
    };
}
