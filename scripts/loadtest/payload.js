// 전송량 감소를 실측하려고 collector 수집 입구에 부하를 넣는 k6 시나리오.
//
// 에이전트가 실제로 지나는 경로 그대로다. 수집 API 가 검증·정규화한 뒤 events 로 발행하고,
// 그 발행 지점에서 PayloadSizeMeter 가 Protobuf 실바이트와 JSON 환산 바이트를 같이 남긴다.
// 발행되는 것은 Protobuf 하나뿐이고 JSON 은 재기만 한다.
//
// 대시보드: scripts/loadtest/dashboard-payload.json
// 이 스크립트와 지표 코드는 수치를 확정하면 같이 걷어낸다.
//
//   준비 (배포서버)
//     sudo kubectl -n edrdog set env deploy/collector-service EDRDOG_COMPARE_JSON=true
//     sudo kubectl -n edrdog rollout status deploy/collector-service --timeout=180s
//     sudo kubectl -n edrdog port-forward svc/collector-service 8082:80 &
//
//   실행
//     k6 run -e COLLECTOR=http://localhost:8082 -e API=https://edrdog-api.duckdns.org \
//            scripts/loadtest/payload.js
//
//   enroll secret 은 데모 계정으로 로그인해 직접 받아 온다. 서버에서 손으로 꺼낼 것이 없다.
//
// 이벤트 구성은 글 본문의 샘플과 맞춰 둔다. 그래야 계산값과 실측을 나란히 놓을 수 있다.

import http from 'k6/http';
import { check } from 'k6';

const COLLECTOR = __ENV.COLLECTOR || 'http://localhost:8082';
const API = __ENV.API || 'http://localhost:8084';
const EMAIL = __ENV.EMAIL || 'test@edrdog.local';      // DemoAccountSeeder 가 심는 계정
const PASSWORD = __ENV.PASSWORD || '1234';
const RATE = Number(__ENV.RATE || 20);            // 초당 배치 수
const DURATION_S = Number(__ENV.DURATION_SECONDS || 120);
const HOSTS = Number(__ENV.HOSTS || 5);           // 단말 수. 파티션에 고르게 퍼지게 한다

export const options = {
  scenarios: {
    ingest: {
      executor: 'constant-arrival-rate',
      rate: RATE,
      timeUnit: '1s',
      duration: `${DURATION_S}s`,
      preAllocatedVUs: 20,
      maxVUs: 60,
    },
  },
  // 크기를 재는 게 목적이라 응답 지연은 보지 않는다. 실패만 막는다.
  thresholds: { checks: ['rate>0.99'] },
};

/** 데모 계정으로 로그인해 그 tenant 의 enroll secret 을 얻는다. 미발급이면 새로 발급한다. */
function enrollSecret() {
  const login = http.post(`${API}/api/auth/login`,
    JSON.stringify({ email: EMAIL, password: PASSWORD }),
    { headers: { 'Content-Type': 'application/json' } });
  if (login.status !== 200) {
    throw new Error(`로그인 실패 (${login.status}): ${login.body}`);
  }
  const bearer = { Authorization: `Bearer ${login.json('token')}` };

  const got = http.get(`${API}/api/tenant/enroll-secret`, { headers: bearer });
  const existing = got.status === 200 ? got.json('enrollSecret') : null;
  if (existing) {
    return existing;
  }
  // 회전시키면 이미 붙어 있는 단말의 재등록이 막힌다. 없을 때만 발급한다.
  const issued = http.post(`${API}/api/tenant/enroll-secret`, null, { headers: bearer });
  if (issued.status !== 200) {
    throw new Error(`enroll secret 발급 실패 (${issued.status}): ${issued.body}`);
  }
  return issued.json('enrollSecret');
}

/** 단말을 미리 등록하고 node_key 를 받는다. 배치마다 새로 등록하면 agent_nodes 가 부풀어 오른다. */
export function setup() {
  const SECRET = enrollSecret();
  const keys = [];
  for (let i = 0; i < HOSTS; i++) {
    const res = http.post(
      `${COLLECTOR}/api/agent/enroll`,
      JSON.stringify({
        enroll_secret: SECRET,
        host_identifier: `loadtest-${i}`,
        platform: 'darwin',
        agent_version: '0.1.0',
      }),
      { headers: { 'Content-Type': 'application/json' } },
    );
    if (res.status !== 200) {
      throw new Error(`enroll 실패 (${res.status}): ${res.body}`);
    }
    keys.push({ host: `loadtest-${i}`, nodeKey: res.json('node_key') });
  }
  return { keys };
}

const SHA256 = 'a'.repeat(64);

/**
 * 배치 한 묶음. 종류를 섞어야 종류별 감소율 패널이 채워진다.
 * tenantId 는 넣지 않는다. 단말이 보낸 조직 태그를 믿으면 다른 조직 데이터에 섞을 수 있어 서버가 심는다.
 */
function batch(host, ts) {
  return [
    {
      host, type: 'process', ts,
      process: '/usr/bin/curl', parent: 'zsh',
      cmdline: 'curl -s http://example.com/payload.sh',
      sha256: SHA256,
      detail: JSON.stringify({ pid: 41233, ppid: 980 }),
    },
    {
      host, type: 'network', ts: ts + 1,
      process: '/usr/bin/curl', destIp: '203.0.113.24', destPort: 443,
      detail: JSON.stringify({ pid: 41233, protocol: 'tcp' }),
    },
    {
      host, type: 'dns', ts: ts + 2,
      process: '/usr/bin/curl', domain: 'example.com',
      detail: JSON.stringify({ qtype: 'A', answers: ['203.0.113.24'] }),
    },
    {
      host, type: 'file', ts: ts + 3,
      process: 'note.txt', cmdline: '/Users/me/Documents/note.txt',
      detail: JSON.stringify({ action: 'WRITE' }),
    },
    {
      host, type: 'script', ts: ts + 4,
      process: 'bash', parent: 'zsh', cmdline: 'bash /Users/me/bin/backup.sh',
      detail: JSON.stringify({ pid: 41300, ppid: 980 }),
    },
    {
      host, type: 'l7', ts: ts + 5,
      process: '/usr/bin/curl', destIp: '203.0.113.24', destPort: 443,
      domain: 'cdn.example.com',
      detail: JSON.stringify({ tlsVersion: 'TLS 1.3', issuer: 'R3' }),
    },
  ];
}

export default function (data) {
  const target = data.keys[Math.floor(Math.random() * data.keys.length)];
  const res = http.post(
    `${COLLECTOR}/api/agent/events`,
    JSON.stringify({ events: batch(target.host, Date.now()) }),
    { headers: { 'Content-Type': 'application/json', 'X-Node-Key': target.nodeKey } },
  );
  // 검증에서 걸리면 발행이 안 되고 지표도 안 쌓인다. 6건이 다 통과해야 한다.
  check(res, {
    '200': (r) => r.status === 200,
    '6건 전부 통과': (r) => r.json('accepted') === 6,
  });
}
