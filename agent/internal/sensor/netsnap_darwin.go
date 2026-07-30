//go:build darwin

package sensor

/*
#include <stdlib.h>
#include <string.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// conn_row 는 소켓 fd 하나에서 뽑아낸 값이다.
//
// cgo 는 C 의 union 을 바이트 배열로만 보여 주기 때문에 Go 에서 soi_proto 나 insi_faddr 를
// 직접 읽으면 오프셋을 손으로 계산해야 한다. 그러면 SDK 가 바뀔 때 조용히 틀린 값을 읽는다.
// 그래서 union 접근은 C 쪽에서 끝내고 Go 로는 평평한 구조체만 넘긴다.
typedef struct {
	int  ok;                    // 1 이면 established TCP 이고 아래 값이 유효하다
	int  port;                  // 원격 포트, 호스트 바이트 순서
	char ip[INET6_ADDRSTRLEN];  // 원격 IP 문자열
} conn_row;

static conn_row edrdog_socket_conn(int pid, int fd) {
	conn_row row;
	memset(&row, 0, sizeof(row));

	struct socket_fdinfo si;
	int n = proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, &si, PROC_PIDFDSOCKETINFO_SIZE);
	if (n < (int)PROC_PIDFDSOCKETINFO_SIZE) {
		return row; // 권한이 없거나 그 사이 닫힌 fd
	}

	// TCP 이면서 established 인 것만 연결로 본다.
	// listen 소켓은 아직 상대가 없고, bind 만 된 UDP 는 목적지가 정해지지 않는다.
	if (si.psi.soi_kind != SOCKINFO_TCP) {
		return row;
	}
	if (si.psi.soi_proto.pri_tcp.tcpsi_state != TSI_S_ESTABLISHED) {
		return row;
	}

	struct in_sockinfo *ini = &si.psi.soi_proto.pri_tcp.tcpsi_ini;

	// insi_vflag 가 IPv4/IPv6 를 알려 준다. AF_INET6 소켓이 v4 매핑 주소를 쥐고 있을 수 있어서
	// soi_family 보다 이쪽이 정확하다. 다만 vflag 가 비어 오는 경우가 있어 family 로 보정한다.
	int v4 = (ini->insi_vflag & INI_IPV4) != 0;
	int v6 = (ini->insi_vflag & INI_IPV6) != 0;
	if (!v4 && !v6) {
		v4 = si.psi.soi_family == AF_INET;
		v6 = si.psi.soi_family == AF_INET6;
	}

	if (v4) {
		if (inet_ntop(AF_INET, &ini->insi_faddr.ina_46.i46a_addr4, row.ip, sizeof(row.ip)) == NULL) {
			return row;
		}
	} else if (v6) {
		if (inet_ntop(AF_INET6, &ini->insi_faddr.ina_6, row.ip, sizeof(row.ip)) == NULL) {
			return row;
		}
	} else {
		return row; // 유닉스 도메인 소켓 등
	}

	row.port = ntohs((uint16_t)ini->insi_fport);
	row.ok = 1;
	return row;
}
*/
import "C"

import (
	"context"
	"fmt"
	"time"
	"unsafe"

	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/event"
)

// maxSnapshotFailures 는 연속 실패를 몇 번까지 참을지다.
// 한 주기 실패는 흔하다(프로세스가 그 사이 죽는다). 계속 실패하면 조용히 0 건으로 도는 것보다
// 센서를 죽여 로그에 남기는 쪽이 낫다.
const maxSnapshotFailures = 5

// NetSnapSensor 는 열린 TCP 연결을 주기마다 훑어 새로 생긴 것만 이벤트로 낸다.
//
// 이 센서만 폴링이다. 이유는 netsnap.go 위쪽 주석에 적었다. eslogger 로 받는 프로세스/파일
// 이벤트와 달리 커널이 밀어 주는 것이 아니라 우리가 물어보는 구조라, 주기보다 짧게 살다 간
// 연결은 놓친다.
type NetSnapSensor struct {
	Factory  event.Factory
	Interval time.Duration
}

// Name 은 센서 이름이다.
func (s *NetSnapSensor) Name() string { return "netsnap" }

// Run 은 Interval 마다 스냅샷을 떠 새 연결만 내보내고 ctx 가 끝나면 멈춘다.
//
// 첫 스냅샷은 기준선이라 이벤트가 나오지 않는다(Differ.New 참고).
func (s *NetSnapSensor) Run(ctx context.Context, out chan<- event.Event) error {
	interval := s.Interval
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	differ := NewDiffer()
	fails := 0
	var lastErr error

	for {
		conns, err := snapshot()
		if err != nil {
			// 한 주기 실패로 센서를 죽이지 않는다. 다음 주기에 다시 시도한다.
			fails++
			lastErr = err
			if fails >= maxSnapshotFailures {
				return fmt.Errorf("소켓 조회가 %d 번 연속 실패했다: %w", fails, lastErr)
			}
		} else {
			fails = 0
			for _, e := range ToEvents(s.Factory, time.Now(), differ.New(conns)) {
				select {
				case out <- e:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}

		select {
		case <-ticker.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// snapshot 은 지금 열려 있는 established TCP 연결을 전부 모은다.
//
// proc_listpids 로 PID 를 훑고, PID 마다 fd 목록을 받아 소켓 fd 를 하나씩 들여다본다.
// 권한이 없어 못 읽는 프로세스는 조용히 건너뛴다. 다른 사용자의 프로세스는 root 로 돌아도
// 일부 실패하는데, 그것 때문에 스냅샷 전체를 버리면 볼 수 있는 것까지 못 본다.
func snapshot() ([]Conn, error) {
	pids, err := listPIDs()
	if err != nil {
		return nil, err
	}

	var conns []Conn
	for _, pid := range pids {
		if pid <= 0 {
			continue // 0 은 kernel_task 다. 소켓이 없다
		}
		path, ok := procPath(pid)
		if !ok {
			continue // 경로를 못 읽으면 누가 연결했는지 못 적는다. 그런 이벤트는 쓸모가 없다
		}
		for _, fd := range listSocketFDs(pid) {
			row := C.edrdog_socket_conn(C.int(pid), C.int(fd))
			if row.ok == 0 {
				continue
			}
			conns = append(conns, Conn{
				PID:        pid,
				Path:       path,
				RemoteIP:   C.GoString(&row.ip[0]),
				RemotePort: int(row.port),
			})
		}
	}
	return conns, nil
}

// listPIDs 는 현재 살아 있는 PID 를 전부 돌려준다.
func listPIDs() ([]int, error) {
	need := C.proc_listpids(C.PROC_ALL_PIDS, 0, nil, 0)
	if need <= 0 {
		return nil, fmt.Errorf("proc_listpids 로 크기를 못 구했다")
	}

	// 크기를 물어본 뒤 실제로 받기까지 사이에 프로세스가 늘 수 있어 여유를 둔다.
	count := int(need)/int(unsafe.Sizeof(C.int32_t(0))) + 64
	buf := make([]C.int32_t, count)

	got := C.proc_listpids(C.PROC_ALL_PIDS, 0, unsafe.Pointer(&buf[0]), C.int(len(buf)*int(unsafe.Sizeof(buf[0]))))
	if got <= 0 {
		return nil, fmt.Errorf("proc_listpids 가 실패했다")
	}

	n := int(got) / int(unsafe.Sizeof(buf[0]))
	pids := make([]int, 0, n)
	for _, p := range buf[:n] {
		pids = append(pids, int(p))
	}
	return pids, nil
}

// listSocketFDs 는 한 프로세스의 소켓 fd 번호를 돌려준다.
// 읽을 수 없으면 빈 목록이다. 권한 부족은 흔한 일이라 오류로 올리지 않는다.
func listSocketFDs(pid int) []int32 {
	need := C.proc_pidinfo(C.int(pid), C.PROC_PIDLISTFDS, 0, nil, 0)
	if need <= 0 {
		return nil
	}

	size := C.int(unsafe.Sizeof(C.struct_proc_fdinfo{}))
	buf := make([]C.struct_proc_fdinfo, int(need)/int(size)+16)

	got := C.proc_pidinfo(C.int(pid), C.PROC_PIDLISTFDS, 0, unsafe.Pointer(&buf[0]), C.int(len(buf))*size)
	if got <= 0 {
		return nil
	}

	var fds []int32
	for _, fi := range buf[:int(got)/int(size)] {
		if fi.proc_fdtype == C.PROX_FDTYPE_SOCKET {
			fds = append(fds, int32(fi.proc_fd))
		}
	}
	return fds
}

// procPath 는 프로세스의 실행 파일 경로를 읽는다. 못 읽으면 두 번째 값이 false 다.
func procPath(pid int) (string, bool) {
	buf := make([]byte, C.PROC_PIDPATHINFO_MAXSIZE)
	n := C.proc_pidpath(C.int(pid), unsafe.Pointer(&buf[0]), C.uint32_t(len(buf)))
	if n <= 0 {
		return "", false
	}
	return string(buf[:n]), true
}
