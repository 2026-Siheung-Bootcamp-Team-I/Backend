#!/usr/bin/env python3
"""
Zeek conn.log 을 EDRdog 수집 API 로 흘려보내는 shipper.

osquery 는 macOS/Windows 모두 실시간 소켓 이벤트를 제대로 주지 못한다
(macOS socket_events 는 OpenBSM 기반이라 신형 macOS 에서 비고, Windows 는 테이블 자체가 없다).
그래서 네트워크 이벤트만 Zeek 가 담당한다.

서버는 손대지 않는다. collector 의 RawEventMapper 가 쿼리명에 socket 이 들어가면 network 로 분류하고
columns.remote_address / remote_port 를 destIp / destPort 로 읽으므로, conn.log 한 줄을
osquery result-log 모양으로 바꿔 기존 /api/osquery/log 로 넣으면 그대로 흘러간다.

  Zeek conn.log ──▶ (이 스크립트) ──▶ /api/osquery/log ──▶ events-raw ──▶ collector ──▶ events

인증도 osquery 와 같다. enroll_secret 으로 한 번 enroll 해 node_key 를 받아 캐시하고,
node_key 가 무효해지면(서버 재설치 등) 자동으로 다시 enroll 한다.

사용:
  sudo -E ./edrdog-zeek-shipper.py --conn-log /var/log/zeek/conn.log

환경변수(기본값은 osquery 플래그와 같은 경로를 쓴다):
  EDR_TLS_HOST      수집 서버 host:port      (기본 값 없음, --tls-host 로도 지정)
  EDR_CERT          서버 cert(PEM) 경로       (기본 /etc/osquery/osquery-server.pem)
  EDR_SECRET        enroll secret 파일 경로   (기본 /etc/osquery/enroll.secret)
  EDR_STATE         node_key 캐시 경로        (기본 /var/osquery/zeek-node-key)
"""

import argparse
import json
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request

DEFAULT_CERT = "/etc/osquery/osquery-server.pem"
DEFAULT_SECRET = "/etc/osquery/enroll.secret"
DEFAULT_STATE = "/var/osquery/zeek-node-key"

# 한 번에 보낼 최대 건수와 최대 대기 시간. osquery 의 logger_tls_period(10초) 와 맞춘다.
BATCH_MAX = 100
BATCH_SECONDS = 10


def log(msg):
    print(f"[edrdog-zeek] {msg}", flush=True)


class Client:
    """수집 API 클라이언트. 서버 cert 를 핀해서 검증한다(osquery --tls_server_certs 와 같은 방식)."""

    def __init__(self, tls_host, cert_path, secret_path, state_path, host_identifier):
        self.base = f"https://{tls_host}"
        self.secret_path = secret_path
        self.state_path = state_path
        self.host_identifier = host_identifier
        self.ctx = ssl.create_default_context(cafile=cert_path)
        self.node_key = self._load_state()

    def _load_state(self):
        try:
            with open(self.state_path) as f:
                return f.read().strip() or None
        except OSError:
            return None

    def _save_state(self, node_key):
        try:
            with open(self.state_path, "w") as f:
                f.write(node_key)
            os.chmod(self.state_path, 0o600)
        except OSError as e:
            log(f"node_key 캐시 실패(계속 진행): {e}")

    def _post(self, path, payload):
        req = urllib.request.Request(
            self.base + path,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, context=self.ctx, timeout=15) as res:
            return json.loads(res.read().decode() or "{}")

    def enroll(self):
        with open(self.secret_path) as f:
            secret = f.read().strip()
        res = self._post(
            "/api/osquery/enroll",
            {
                "enroll_secret": secret,
                "host_identifier": self.host_identifier,
                # 서버는 platform 으로 수집 스케줄을 고르는데, 네트워크는 스케줄과 무관하다.
                # osquery 노드와 같은 host 로 붙으므로 기존 노드를 그대로 재사용한다.
                "platform_type": "darwin",
            },
        )
        key = res.get("node_key")
        if not key:
            raise RuntimeError(f"enroll 실패(enroll secret 확인 필요): {res}")
        self.node_key = key
        self._save_state(key)
        log(f"enroll 완료 (host={self.host_identifier})")
        return key

    def send(self, records):
        """result-log 배치 발행. node_key 가 무효면 한 번 재-enroll 후 재시도."""
        if not self.node_key:
            self.enroll()
        payload = {"node_key": self.node_key, "log_type": "result", "data": records}
        res = self._post("/api/osquery/log", payload)
        if res.get("node_invalid"):
            log("node_key 무효 → 재-enroll")
            self.enroll()
            payload["node_key"] = self.node_key
            res = self._post("/api/osquery/log", payload)
        return not res.get("node_invalid", False)


def to_record(conn, host_identifier):
    """
    Zeek conn.log 한 줄(JSON) → osquery result-log 레코드.

    쿼리명을 socket_events 로 둬야 collector 의 classify 가 network 로 분류한다.
    목적지만 채운다. Zeek 는 어떤 프로세스가 낸 연결인지 모르므로 path/cmdline 은 비운다
    (프로세스 상관은 osquery 프로세스 이벤트 쪽이 담당).
    """
    dest_ip = conn.get("id.resp_h")
    dest_port = conn.get("id.resp_p")
    ts = conn.get("ts")
    if not dest_ip or ts is None:
        return None
    return {
        "name": "socket_events",
        "hostIdentifier": host_identifier,
        "unixTime": str(int(float(ts))),
        "action": "added",
        "columns": {
            "remote_address": str(dest_ip),
            "remote_port": str(dest_port) if dest_port is not None else "0",
            # 참고용. collector 는 network 이벤트에서 cmdline 을 그대로 싣는다.
            "cmdline": f"zeek proto={conn.get('proto', '')} bytes={conn.get('orig_bytes', 0)}",
            "time": str(int(float(ts))),
        },
    }


def tail(path):
    """파일 끝부터 따라 읽는다. 로테이션(재생성/truncate)되면 다시 연다."""
    while not os.path.exists(path):
        log(f"conn.log 대기 중: {path}")
        time.sleep(3)
    f = open(path)
    f.seek(0, os.SEEK_END)
    inode = os.fstat(f.fileno()).st_ino
    while True:
        line = f.readline()
        if line:
            yield line
            continue
        time.sleep(0.5)
        try:
            if os.stat(path).st_ino != inode or os.stat(path).st_size < f.tell():
                log("conn.log 로테이션 감지 → 다시 연다")
                f.close()
                f = open(path)
                inode = os.fstat(f.fileno()).st_ino
        except FileNotFoundError:
            log("conn.log 사라짐 → 재생성 대기")
            f.close()
            while not os.path.exists(path):
                time.sleep(3)
            f = open(path)
            inode = os.fstat(f.fileno()).st_ino


def main():
    p = argparse.ArgumentParser(description="Zeek conn.log → EDRdog 수집 API")
    p.add_argument("--conn-log", required=True, help="Zeek conn.log 경로 (JSON 라인 형식)")
    p.add_argument("--tls-host", default=os.environ.get("EDR_TLS_HOST"), help="수집 서버 host:port")
    p.add_argument("--cert", default=os.environ.get("EDR_CERT", DEFAULT_CERT))
    p.add_argument("--secret", default=os.environ.get("EDR_SECRET", DEFAULT_SECRET))
    p.add_argument("--state", default=os.environ.get("EDR_STATE", DEFAULT_STATE))
    p.add_argument("--host-identifier", default=socket.gethostname(),
                   help="osquery --host_identifier=hostname 과 같은 값이어야 한 기기로 합쳐진다")
    args = p.parse_args()

    if not args.tls_host:
        p.error("--tls-host 또는 EDR_TLS_HOST 가 필요하다 (예: edrdog.example.com:30443)")

    client = Client(args.tls_host, args.cert, args.secret, args.state, args.host_identifier)
    log(f"시작: {args.conn_log} → {args.tls_host} (host={args.host_identifier})")

    batch = []
    last_flush = time.time()
    for line in tail(args.conn_log):
        line = line.strip()
        if not line or line.startswith("#"):
            continue   # TSV 헤더 등 JSON 이 아닌 줄은 건너뛴다
        try:
            rec = to_record(json.loads(line), args.host_identifier)
        except json.JSONDecodeError:
            continue
        if rec:
            batch.append(rec)

        due = len(batch) >= BATCH_MAX or (batch and time.time() - last_flush >= BATCH_SECONDS)
        if not due:
            continue
        try:
            client.send(batch)
            log(f"발행 {len(batch)}건")
            batch = []
            last_flush = time.time()
        except (urllib.error.URLError, ssl.SSLError, OSError) as e:
            # 서버가 잠깐 죽어도 배치를 버리지 않고 다음 주기에 다시 시도한다.
            log(f"발행 실패(다음 주기 재시도): {e}")
            last_flush = time.time()
            if len(batch) > BATCH_MAX * 10:
                log("버퍼가 너무 커져 오래된 것부터 버린다")
                batch = batch[-BATCH_MAX:]


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception as e:   # noqa: BLE001 - 최상위에서 원인만 찍고 종료
        log(f"중단: {e}")
        sys.exit(1)
