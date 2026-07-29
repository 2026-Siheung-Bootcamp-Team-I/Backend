/*
 * osquery 수집 API 계단식 부하 스크립트.
 *
 * 목적은 "API 가 몇 RPS 를 받나"가 아니라 "파이프라인이 초당 몇 이벤트를 끝까지 소화하나"다.
 * api → events-raw → collector → events → archiver → ClickHouse 가 한 사슬이고,
 * archiver 가 이벤트 1건당 ClickHouse INSERT 1회를 동기로 날리므로 거기가 먼저 막힌다.
 * 그래서 부하는 eps(events/sec) 로 지정하고, 마지막에 ClickHouse 적재량으로 실제 소화량을 잰다.
 *
 * 실행:
 *   k6 run scripts/loadtest/osquery-ramp.js
 *   k6 run -e EPS_STEPS=50,100,300,600 -e STEP_SEC=120 scripts/loadtest/osquery-ramp.js
 *
 * 사전 조건:
 *   - api-service 기동 (기본 http://localhost:8084)
 *   - collector / detector / archiver 기동
 *   - kind 클러스터에 kafka / clickhouse / mysql 기동
 *   - 데모 계정 필요: api-service 를 DEMO_SEED=true 로 띄우거나, EMAIL/PASSWORD 를 직접 넘긴다
 *   - 오래 돌릴 거면 서비스 쪽 OTEL_TRACE_SAMPLING 을 0.05 정도로 낮춘다
 *     (전량 샘플링이면 otel-lgtm PVC 5Gi 가 몇 시간 만에 찬다)
 *
 * 보는 곳:
 *   Grafana(http://localhost:3000) EDRdog Overview 의 컨슈머 랙. 랙이 우상향으로 꺾이는
 *   계단이 파이프라인 상한이다. k6 의 p95 는 API 가 Kafka 에 비동기 발행만 하고 응답해서
 *   뒤가 막혀도 한동안 예쁘게 나온다. 랙을 봐야 한다.
 */
import http from 'k6/http';
import exec from 'k6/execution';
import { check, sleep } from 'k6';
import { Counter } from 'k6/metrics';

const API = __ENV.API_URL || 'http://localhost:8084';
const CH = __ENV.CH_URL || 'http://localhost:8123';
const API_KEY = __ENV.EDRDOG_API_KEY || 'dev-api-key';
const EMAIL = __ENV.EMAIL || 'test@edrdog.local';
const PASSWORD = __ENV.PASSWORD || '1234';

const CH_USER = __ENV.CH_USER || 'edrdog';
const CH_PASSWORD = __ENV.CH_PASSWORD || 'edrdog';
const CH_DB = __ENV.CH_DB || 'edrdog';

/** 요청 1건에 실어 보내는 result-log 개수. osquery 도 배치로 보낸다. */
const BATCH = Number(__ENV.BATCH || 10);
/** 가짜 엔드포인트 수. host 단위로 파티션이 갈리므로 너무 적으면 한 파티션에 쏠린다. */
const HOSTS = Number(__ENV.HOSTS || 20);
/** 계단 목표치(eps). 각 계단마다 STEP_SEC 만큼 평탄하게 유지한다. */
const EPS_STEPS = (__ENV.EPS_STEPS || '50,100,300,600').split(',').map(Number);
const STEP_SEC = Number(__ENV.STEP_SEC || 120);
const RAMP_SEC = Number(__ENV.RAMP_SEC || 5);
/**
 * 탐지 룰에 걸리는 이벤트 비율. 기본 0.
 * 0 이 아니면 alert 가 생겨 MySQL 적재 + Slack webhook + responder 조치까지 같이 돈다.
 * webhook 이 등록된 tenant 로 돌리면 실제 Slack 으로 알림이 쏟아지니 켤 때 확인할 것.
 */
const ALERT_RATIO = Number(__ENV.ALERT_RATIO || 0);

/** 계단마다 짧은 램프 + 긴 유지. 유지 구간이 평탄해야 계단별로 비교가 된다. */
function buildStages() {
  const stages = [];
  for (const eps of EPS_STEPS) {
    const rate = eps / BATCH;
    stages.push({ duration: `${RAMP_SEC}s`, target: rate });
    stages.push({ duration: `${STEP_SEC}s`, target: rate });
  }
  return stages;
}

const eventsSent = new Counter('edrdog_events_sent');

export const options = {
  scenarios: {
    ramp: {
      executor: 'ramping-arrival-rate',
      startRate: 0,
      timeUnit: '1s',
      preAllocatedVUs: 20,
      maxVUs: Number(__ENV.MAX_VUS || 200),
      stages: buildStages(),
      gracefulStop: '30s',
    },
  },
  thresholds: {
    // 임계 초과해도 중단하지 않는다. 어느 계단에서 깨지는지가 보고 싶은 것이라서.
    http_req_failed: [{ threshold: 'rate<0.01', abortOnFail: false }],
    'http_req_duration{name:log}': [{ threshold: 'p(95)<500', abortOnFail: false }],
  },
  teardownTimeout: '15m',
  summaryTrendStats: ['avg', 'min', 'med', 'p(95)', 'p(99)', 'max'],
};

const JSON_HEADERS = { 'Content-Type': 'application/json' };

function chHeaders() {
  return {
    'Content-Type': 'text/plain',
    'X-ClickHouse-User': CH_USER,
    'X-ClickHouse-Key': CH_PASSWORD,
    'X-ClickHouse-Database': CH_DB,
  };
}

/** 부하로 적재된 행만 센다(기존 데모 데이터와 섞이지 않게 host 접두어로 거른다). */
function countLoadtestRows() {
  const res = http.post(
    CH,
    "SELECT count() FROM edrdog.events WHERE host LIKE 'loadtest-%'",
    { headers: chHeaders(), tags: { name: 'ch_count' } },
  );
  if (res.status !== 200) {
    return null;
  }
  return Number(String(res.body).trim());
}

export function setup() {
  // 1) 로그인 → 세션 토큰
  const login = http.post(`${API}/api/auth/login`, JSON.stringify({ email: EMAIL, password: PASSWORD }), {
    headers: JSON_HEADERS,
    tags: { name: 'login' },
  });
  if (login.status !== 200) {
    throw new Error(
      `로그인 실패(${login.status}). DEMO_SEED=true 로 api-service 를 띄웠는지, ` +
        `아니면 -e EMAIL=... -e PASSWORD=... 를 넘겼는지 확인. body=${login.body}`,
    );
  }
  const token = login.json('token');
  const authHeaders = { ...JSON_HEADERS, Authorization: `Bearer ${token}`, 'X-API-Key': API_KEY };

  // 2) enroll secret 조회, 없으면 발급
  let secret = http.get(`${API}/api/tenant/enroll-secret`, { headers: authHeaders, tags: { name: 'enroll_secret' } })
    .json('enrollSecret');
  if (!secret) {
    const rotated = http.post(`${API}/api/tenant/enroll-secret`, null, {
      headers: authHeaders,
      tags: { name: 'enroll_secret' },
    });
    if (rotated.status !== 200) {
      throw new Error(`enroll secret 발급 실패(${rotated.status}): ${rotated.body}`);
    }
    secret = rotated.json('enrollSecret');
  }

  // 3) 가짜 엔드포인트 enroll → node_key 확보
  const nodeKeys = [];
  for (let i = 0; i < HOSTS; i++) {
    const host = `loadtest-${i}`;
    const res = http.post(
      `${API}/api/osquery/enroll`,
      JSON.stringify({ enroll_secret: secret, host_identifier: host, platform_type: 'windows' }),
      { headers: JSON_HEADERS, tags: { name: 'enroll' } },
    );
    const key = res.json('node_key');
    if (!key) {
      throw new Error(`enroll 실패: host=${host} status=${res.status} body=${res.body}`);
    }
    nodeKeys.push({ host, key });
  }

  const rowsBefore = countLoadtestRows();
  const plan = EPS_STEPS.map((e) => `${e}eps`).join(' → ');
  console.log(`[setup] hosts=${HOSTS} batch=${BATCH} 계단: ${plan} (각 ${STEP_SEC}s)`);
  console.log(`[setup] ClickHouse loadtest 행 수(시작): ${rowsBefore}`);

  return { nodeKeys, rowsBefore, startedAt: Date.now() };
}

const BENIGN_PROCESSES = [
  { path: 'C:\\Windows\\System32\\svchost.exe', parent: 'services.exe', cmdline: 'svchost.exe -k netsvcs' },
  { path: 'C:\\Program Files\\Git\\bin\\git.exe', parent: 'code.exe', cmdline: 'git status' },
  { path: 'C:\\Windows\\System32\\notepad.exe', parent: 'explorer.exe', cmdline: 'notepad.exe memo.txt' },
  { path: 'C:\\Program Files\\nodejs\\node.exe', parent: 'code.exe', cmdline: 'node server.js' },
];

/** 다운로드로 간주되는 80/443/8080 은 피한다. 그 포트를 쓰면 R2(CRITICAL) 가 줄줄이 터진다. */
const BENIGN_PORTS = [3306, 5432, 9418, 8443];

function pick(arr, i) {
  return arr[i % arr.length];
}

function processEvent(host, now, i) {
  const p = pick(BENIGN_PROCESSES, i);
  return {
    name: 'process_events',
    hostIdentifier: host,
    unixTime: now,
    action: 'added',
    columns: { path: p.path, parent: p.parent, cmdline: p.cmdline, time: String(now) },
  };
}

function networkEvent(host, now, i) {
  return {
    name: 'socket_events',
    hostIdentifier: host,
    unixTime: now,
    action: 'added',
    columns: {
      path: 'C:\\Program Files\\app\\sync.exe',
      cmdline: 'sync.exe --daemon',
      remote_address: `10.0.${i % 255}.${(i * 7) % 255}`,
      remote_port: String(pick(BENIGN_PORTS, i)),
      time: String(now),
    },
  };
}

function fileEvent(host, now, i) {
  return {
    name: 'file_events',
    hostIdentifier: host,
    unixTime: now,
    action: 'added',
    columns: { target_path: `C:\\Users\\dev\\Documents\\report-${i}.docx`, time: String(now) },
  };
}

/** R3(SCRIPT_FROM_TEMP_PATH, MEDIUM) 를 의도적으로 완성시키는 이벤트. ALERT_RATIO 로만 섞인다. */
function alertingScriptEvent(host, now, i) {
  return {
    name: 'script_events',
    hostIdentifier: host,
    unixTime: now,
    action: 'added',
    columns: { path: `C:\\Users\\dev\\AppData\\Local\\Temp\\stage-${i}.ps1`, cmdline: `C:\\Users\\dev\\AppData\\Local\\Temp\\stage-${i}.ps1 -enc`, time: String(now) },
  };
}

/** 정상 이벤트 3종을 섞어 배치를 만든다. 타입이 섞여야 collector 매핑과 detector 버퍼가 실제처럼 돈다. */
function buildBatch(host, seed) {
  const now = Math.floor(Date.now() / 1000);
  const rows = [];
  for (let i = 0; i < BATCH; i++) {
    const n = seed + i;
    if (ALERT_RATIO > 0 && Math.random() < ALERT_RATIO) {
      rows.push(alertingScriptEvent(host, now, n));
      continue;
    }
    const mod = n % 5;
    if (mod === 3) {
      rows.push(networkEvent(host, now, n));
    } else if (mod === 4) {
      rows.push(fileEvent(host, now, n));
    } else {
      rows.push(processEvent(host, now, n));
    }
  }
  return rows;
}

export default function (data) {
  const node = data.nodeKeys[exec.vu.idInTest % data.nodeKeys.length];
  const body = JSON.stringify({
    node_key: node.key,
    log_type: 'result',
    data: buildBatch(node.host, exec.scenario.iterationInTest),
  });

  const res = http.post(`${API}/api/osquery/log`, body, {
    headers: JSON_HEADERS,
    tags: { name: 'log' },
  });

  const ok = check(res, {
    'status 200': (r) => r.status === 200,
    'node_invalid=false': (r) => r.json('node_invalid') === false,
  });
  if (ok) {
    eventsSent.add(BATCH);
  }
}

/**
 * 부하가 끝난 뒤 ClickHouse 적재가 멈출 때까지 기다린다.
 * 이 "드레인 시간"이 실제 상한을 말해준다. 부하 중 밀린 만큼을 소화하는 데 걸린 시간이고,
 * 여기서 나오는 평균 적재 eps 가 archiver 가 실제로 낼 수 있는 처리량이다.
 */
export function teardown(data) {
  const sentSeconds = (Date.now() - data.startedAt) / 1000;
  let last = countLoadtestRows();
  let stable = 0;
  const drainStart = Date.now();

  console.log(`[teardown] 부하 종료. 적재 드레인 대기 시작 (현재 ${last} 행)`);
  while (stable < 3 && (Date.now() - drainStart) / 1000 < 600) {
    sleep(5);
    const now = countLoadtestRows();
    if (now === null) {
      console.warn('[teardown] ClickHouse 조회 실패. 드레인 측정 중단');
      return;
    }
    const delta = now - last;
    console.log(`[teardown] +${delta} 행 (누적 ${now}, 최근 5s 평균 ${(delta / 5).toFixed(1)} eps)`);
    stable = delta === 0 ? stable + 1 : 0;
    last = now;
  }

  const drainSeconds = (Date.now() - drainStart) / 1000;
  const inserted = last - (data.rowsBefore || 0);
  console.log('');
  console.log('=== 적재 결과 ===');
  console.log(`ClickHouse 적재 행: ${inserted}`);
  console.log(`부하 구간: ${sentSeconds.toFixed(0)}s, 드레인 추가 대기: ${drainSeconds.toFixed(0)}s`);
  console.log(`전체 평균 적재 처리량: ${(inserted / (sentSeconds + drainSeconds)).toFixed(1)} eps`);
  console.log('드레인이 길게 걸렸다면 그 계단에서 이미 상한을 넘긴 것이다.');
}
