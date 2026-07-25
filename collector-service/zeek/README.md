# Zeek — 네트워크 이벤트 수집

osquery 는 macOS/Windows 어느 쪽도 실시간 네트워크 이벤트를 제대로 주지 못한다.

- **macOS**: `socket_events` 가 OpenBSM 기반인데 애플이 사실상 걷어냈다. 플래그(`--disable_audit=false`,
  `--audit_allow_sockets=true`)를 다 켜도 이벤트가 0건이다 (macOS 26 에서 실측).
- **Windows**: core osquery 에 실시간 소켓 테이블 자체가 없다. 그래서 서버가 내려주는 Windows 스케줄에는
  네트워크 쿼리가 아예 없다.

그래서 네트워크만 Zeek 가 담당한다. 프로세스·파일 이벤트는 그대로 osquery 가 맡는다.

## 서버는 손대지 않는다

collector 의 `RawEventMapper` 는 쿼리명에 `socket` 이 들어가면 network 로 분류하고
`columns.remote_address` / `remote_port` 를 `destIp` / `destPort` 로 읽는다. 그래서 Zeek `conn.log` 한 줄을
osquery result-log 모양으로 바꿔 **기존 수집 API 로 넣으면** 그대로 흘러간다. 새 엔드포인트도 새 서비스도 없다.

```
Zeek conn.log ──▶ edrdog-zeek-shipper.py ──▶ /api/osquery/log ──▶ events-raw ──▶ collector ──▶ events
                                              (osquery 와 같은 enroll secret / node_key / 서버 cert)
```

`--host_identifier` 를 osquery 와 같은 값(hostname)으로 두므로 대시보드에서 **한 기기로 합쳐진다.**

## 실행 (macOS)

전제: 이 기기에 osquery 가 이미 EDRdog 로 붙어 있어야 한다(`/etc/osquery/enroll.secret`,
`/etc/osquery/osquery-server.pem`). 온보딩 2번을 먼저 끝낼 것.

```bash
brew install zeek

# 1) 캡처 (로그는 실행한 디렉터리에 생긴다)
mkdir -p ~/zeek-logs && cd ~/zeek-logs
sudo zeek -C -i en0 LogAscii::use_json=T local

# 2) 다른 터미널에서 shipper
sudo ./edrdog-zeek-shipper.py \
  --conn-log ~/zeek-logs/conn.log \
  --tls-host <수집서버>:30443
```

- **`-C` 는 필수다.** en0 가 체크섬 오프로딩(TSO)을 쓰기 때문에 없으면 Zeek 가 체크섬 오류로 패킷을 전부 버린다.
- 인터페이스는 `route get default` 로 확인한다(보통 `en0`).
- `sudo` 가 필요한 이유는 두 가지다: BPF 디바이스(`/dev/bpf*`)가 root 전용, enroll secret 파일이 0600.
- `zeekctl` 없이 직접 띄우면 로그 로테이션이 걸리지 않아 `conn.log` 가 계속 append 된다. shipper 는
  그래도 로테이션·재생성을 감지해 다시 연다.

## 확인

Zeek 는 **연결이 끝난 뒤** conn.log 에 쓴다. TCP 정상 종료면 약 5초 뒤다(`tcp_close_delay`).
진행 중인 연결은 안 찍히므로, curl 몇 번 치고 10~20초 기다린 뒤에 본다.

```bash
tail -f ~/zeek-logs/conn.log        # 줄이 쌓이는지
```

서버 쪽은 위협 지도(`GET /api/events/geo`)에 국가별 건수가 늘어나면 끝까지 도달한 것이다.
지도는 **사설 IP 를 제외**하므로(`PrivateIp.isPublic`) 외부로 나가는 연결이 있어야 보인다.

## 테스트

변환 로직(순수)만 단위 테스트가 있다. 이 부분이 어긋나면 이벤트가 조용히 버려지거나 network 가 아닌
타입으로 분류되므로, 필드 이름을 바꿀 때는 여기부터 고친다.

```bash
python3 -m unittest discover collector-service/zeek
```

## 한계 (지금 상태)

- **프로세스 상관 없음**: Zeek 는 어떤 프로세스가 낸 연결인지 모른다. 그래서 network 이벤트의
  `process` 는 비어 있다. 프로세스 기준 판정은 osquery 이벤트가 담당한다.
- **수동 실행**: launchd 등록이 없다. 터미널을 닫으면 캡처도 멈춘다. 상시 수집이 필요하면
  Zeek 와 shipper 둘 다 데몬으로 올려야 한다.
- **Windows 미지원**: 같은 방식(Zeek + shipper)으로 붙일 수는 있으나 아직 안 만들었다.
