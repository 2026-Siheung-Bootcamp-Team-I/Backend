//go:build darwin

package sensor

/*
#include <stdlib.h>
#include <string.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// owner_row 는 소켓 fd 하나에서 뽑은 값이다.
// netsnap_darwin.go 의 헬퍼와 합치지 마라. 그쪽은 원격 주소만, 여기는 로컬 포트까지 읽어야 한다.
// union 접근은 C 에서 끝낸다. Go 로 옮겨 오프셋을 손으로 계산하면 SDK 가 바뀌는 날 틀린 값을 읽는다.
typedef struct {
	int  ok;                     // 1 이면 상대가 있는 TCP 소켓이고 아래 값이 유효하다
	int  lport;                  // 로컬 포트, 호스트 바이트 순서
	int  fport;                  // 원격 포트
	char faddr[INET6_ADDRSTRLEN]; // 원격 IP 문자열
} owner_row;

static owner_row edrdog_socket_owner(int pid, int fd) {
	owner_row row;
	memset(&row, 0, sizeof(row));

	struct socket_fdinfo si;
	int n = proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, &si, PROC_PIDFDSOCKETINFO_SIZE);
	if (n < (int)PROC_PIDFDSOCKETINFO_SIZE) {
		return row; // 권한이 없거나 그 사이 닫힌 fd
	}
	if (si.psi.soi_kind != SOCKINFO_TCP) {
		return row;
	}

	struct in_sockinfo *ini = &si.psi.soi_proto.pri_tcp.tcpsi_ini;

	// vflag 로 IPv4/IPv6 를 가른다. vflag 가 비어 오면 family 로 보정한다.
	int v4 = (ini->insi_vflag & INI_IPV4) != 0;
	int v6 = (ini->insi_vflag & INI_IPV6) != 0;
	if (!v4 && !v6) {
		v4 = si.psi.soi_family == AF_INET;
		v6 = si.psi.soi_family == AF_INET6;
	}

	if (v4) {
		if (inet_ntop(AF_INET, &ini->insi_faddr.ina_46.i46a_addr4, row.faddr, sizeof(row.faddr)) == NULL) {
			return row;
		}
	} else if (v6) {
		if (inet_ntop(AF_INET6, &ini->insi_faddr.ina_6, row.faddr, sizeof(row.faddr)) == NULL) {
			return row;
		}
	} else {
		return row; // 유닉스 도메인 소켓 등
	}

	row.lport = ntohs((uint16_t)ini->insi_lport);
	row.fport = ntohs((uint16_t)ini->insi_fport);

	// 상대 포트가 없으면 listen 소켓이다. 로컬 포트가 겹쳐 엉뚱한 주인을 가리키므로 뺀다.
	if (row.fport == 0) {
		return row;
	}
	row.ok = 1;
	return row;
}
*/
import "C"

import (
	"sync"
	"time"
)

// 흐름의 4-튜플로 그 소켓을 연 프로세스를 찾는다. L7 센서가 SNI 에 프로세스를 붙일 때 쓴다.
// 캡처(pcap_darwin.go)와 주고받는 심볼이 없어 파일을 갈라 둔다.

const (
	// ownerCacheTTL 은 소켓 스캔 결과를 얼마나 재활용할지다.
	// 스캔은 전 프로세스의 fd 를 훑는다. 캐시가 없으면 ClientHello 가 몰릴 때마다 CPU 가 튄다.
	ownerCacheTTL = 500 * time.Millisecond

	// ownerRescanFloor 는 못 찾았을 때 다시 훑기까지의 최소 간격이다.
	// 이미 닫힌 소켓은 몇 번을 훑어도 안 나온다. 이 간격이 없으면 그런 조회가 스캔만 반복시킨다.
	ownerRescanFloor = 50 * time.Millisecond
)

// ownerKey 는 소켓 하나를 가리키는 4-튜플 중 우리가 아는 부분이다.
type ownerKey struct {
	localPort  int
	remoteIP   string
	remotePort int
}

// ProcOwner 는 libproc 으로 소켓의 주인 프로세스를 찾는다. SocketOwner 를 만족한다.
type ProcOwner struct {
	mu      sync.Mutex
	scanned time.Time
	exact   map[ownerKey]string
	byPort  map[int]string

	// 테스트에서 갈아 끼운다. 실제 스캔은 root 와 살아 있는 소켓이 있어야 한다.
	scan func() (map[ownerKey]string, map[int]string)
	now  func() time.Time
}

// NewProcOwner 는 소유자 조회기를 만든다.
func NewProcOwner() *ProcOwner {
	return &ProcOwner{scan: scanSocketOwners, now: time.Now}
}

// Lookup 은 로컬 포트로 프로세스 실행 경로를 찾는다. 못 찾으면 빈 문자열이다.
func (o *ProcOwner) Lookup(localPort int, remoteIP string, remotePort int) string {
	o.mu.Lock()
	defer o.mu.Unlock()

	now := o.now()
	fresh := o.exact != nil && now.Sub(o.scanned) <= ownerCacheTTL
	if fresh {
		if path := o.lookup(localPort, remoteIP, remotePort); path != "" {
			return path
		}
	}
	// 캐시에 없다. 마지막 스캔 뒤에 열린 소켓일 수 있으니 다시 훑어 본다.
	if now.Sub(o.scanned) < ownerRescanFloor {
		return ""
	}
	o.exact, o.byPort = o.scan()
	o.scanned = now
	return o.lookup(localPort, remoteIP, remotePort)
}

func (o *ProcOwner) lookup(localPort int, remoteIP string, remotePort int) string {
	if path := o.exact[ownerKey{localPort, remoteIP, remotePort}]; path != "" {
		return path
	}
	// 이 물러남을 지우면 v4 매핑 IPv6 소켓처럼 표기가 어긋나는 흐름의 주인을 못 찾는다.
	return o.byPort[localPort]
}

// scanSocketOwners 는 지금 열린 TCP 소켓의 주인을 전부 모은다.
// 못 읽는 프로세스는 건너뛴다. 여기서 포기하면 볼 수 있었던 소켓의 주인까지 같이 잃는다.
func scanSocketOwners() (map[ownerKey]string, map[int]string) {
	exact := make(map[ownerKey]string)
	byPort := make(map[int]string)

	pids, err := listPIDs()
	if err != nil {
		return exact, byPort
	}
	for _, pid := range pids {
		if pid <= 0 {
			continue
		}
		path, ok := procPath(pid)
		if !ok {
			continue
		}
		for _, fd := range listSocketFDs(pid) {
			row := C.edrdog_socket_owner(C.int(pid), C.int(fd))
			if row.ok == 0 {
				continue
			}
			lport := int(row.lport)
			exact[ownerKey{lport, C.GoString(&row.faddr[0]), int(row.fport)}] = path
			byPort[lport] = path
		}
	}
	return exact, byPort
}
