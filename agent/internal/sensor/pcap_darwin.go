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
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	// maxBPFDevices 는 /dev/bpfN 을 몇 번까지 열어 볼지다. macOS 는 기본 256개를 둔다.
	maxBPFDevices = 256

	// captureBufferSize 는 커널이 패킷을 모아 둘 버퍼 크기다. macOS 기본 상한값이다.
	// 기본값 4KB 로 두면 ClientHello 두 장에 차고 그 뒤 패킷은 커널이 말없이 버린다.
	captureBufferSize = 512 << 10

	// captureReadTimeout 은 읽기가 최대 얼마나 막혀 있을지다.
	// 시한이 없으면 조용한 링크에서 read 가 영영 잠들어 Close 가 읽기 루프를 못 깨운다.
	captureReadTimeout = 250 * time.Millisecond

	// capturePacketQueue 는 읽기 루프와 센서 사이의 큐 길이다.
	// 줄이면 센서가 잠깐 밀릴 때 커널 버퍼까지 차서 프레임을 한꺼번에 잃는다.
	capturePacketQueue = 2048
)

// BPFCapture 는 /dev/bpf 로 프레임을 읽어 채널로 흘린다. PacketSource 를 만족한다.
type BPFCapture struct {
	fd    int
	iface string
	log   *slog.Logger

	packets chan []byte
	stop    chan struct{}
	once    sync.Once
	wg      sync.WaitGroup
	dropped atomic.Uint64
}

// OpenCapture 는 기본 라우트가 나가는 인터페이스에 붙어 캡처를 시작한다.
func OpenCapture(log *slog.Logger) (*BPFCapture, error) {
	iface, err := defaultInterface()
	if err != nil {
		return nil, err
	}
	return OpenCaptureOn(iface, log)
}

// OpenCaptureOn 은 지정한 인터페이스에 붙어 캡처를 시작한다.
func OpenCaptureOn(iface string, log *slog.Logger) (*BPFCapture, error) {
	if log == nil {
		log = slog.Default()
	}

	fd, err := openBPFDevice()
	if err != nil {
		return nil, err
	}
	if err := configureBPF(fd, iface, log); err != nil {
		unix.Close(fd)
		return nil, err
	}

	// 읽기 크기는 커널이 정한 버퍼 크기와 정확히 같아야 한다. 작게 읽으면 EINVAL 이다.
	bufLen, err := unix.IoctlGetInt(fd, unix.BIOCGBLEN)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("BPF 버퍼 크기를 못 읽었다: %w", err)
	}

	c := &BPFCapture{
		fd:      fd,
		iface:   iface,
		log:     log,
		packets: make(chan []byte, capturePacketQueue),
		stop:    make(chan struct{}),
	}
	c.wg.Add(1)
	go c.readLoop(bufLen)

	log.Info("패킷 캡처를 시작했다", "iface", iface, "buffer", bufLen, "snaplen", CaptureSnapLen)
	return c, nil
}

// Packets 는 캡처한 프레임을 준다.
func (c *BPFCapture) Packets() <-chan []byte { return c.packets }

// Close 는 캡처를 멈추고 BPF 장치를 놓는다.
func (c *BPFCapture) Close() error {
	var err error
	c.once.Do(func() {
		close(c.stop)
		// 읽기 루프가 끝난 뒤에 fd 를 닫는다. 먼저 닫으면 그 번호를 재배정받은 남의 fd 를 읽는다.
		c.wg.Wait()
		err = unix.Close(c.fd)
		if n := c.dropped.Load(); n > 0 {
			c.log.Warn("캡처를 닫는다", "iface", c.iface, "dropped", n)
		}
	})
	return err
}

// readLoop 는 BPF 장치에서 버퍼를 읽어 패킷으로 쪼갠다.
func (c *BPFCapture) readLoop(bufLen int) {
	defer c.wg.Done()
	defer close(c.packets)

	buf := make([]byte, bufLen)
	for {
		select {
		case <-c.stop:
			return
		default:
		}

		n, err := unix.Read(c.fd, buf)
		if err != nil {
			if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
				continue // 읽기 시한이 지났거나 시그널에 깨졌다. 정상이다
			}
			select {
			case <-c.stop:
				// Close 가 부른 오류다. 조용히 끝낸다.
			default:
				c.log.Error("BPF 읽기가 실패해 캡처를 멈춘다", "iface", c.iface, "err", err)
			}
			return
		}
		splitBPFBuffer(buf[:n], c.emit)
	}
}

// emit 은 프레임 하나를 채널로 넘긴다. 큐가 차면 막지 않고 버린 뒤 로그에 남긴다.
// 여기서 막으면 읽기 루프가 서고 커널 버퍼가 차서 한 장 대신 수백 장을 잃는다.
func (c *BPFCapture) emit(frame []byte) {
	select {
	case c.packets <- frame:
	default:
		if n := c.dropped.Add(1); n%1000 == 1 {
			c.log.Warn("패킷 큐가 차서 버린다", "iface", c.iface, "dropped", n)
		}
	}
}

// splitBPFBuffer 는 read 한 번으로 받은 버퍼를 패킷들로 쪼갠다.
// BPF 는 여러 장을 묶어 준다. 첫 장만 읽으면 나머지를 잃고, 다음 위치를 틀리면 전부 쓰레기가 된다.
func splitBPFBuffer(buf []byte, emit func([]byte)) {
	for off := 0; off+bpfHdrFieldsLen <= len(buf); {
		hdrLen := int(binary.LittleEndian.Uint16(buf[off+bpfHdrLenOffset:]))
		capLen := int(binary.LittleEndian.Uint32(buf[off+bpfCapLenOffset:]))

		start := off + hdrLen
		end := start + capLen
		if hdrLen < bpfHdrFieldsLen || capLen < 0 || end > len(buf) {
			// 커널이 담은 방식과 우리가 읽는 방식이 어긋났다. 남은 바이트는 믿을 수 없다.
			return
		}
		if capLen > 0 {
			// 버퍼는 다음 read 가 덮어쓴다. 넘기기 전에 복사해야 한다.
			frame := make([]byte, capLen)
			copy(frame, buf[start:end])
			emit(frame)
		}
		off += bpfWordAlign(hdrLen + capLen)
	}
}

// bpf_hdr 의 필드 위치와 길이.
// unix.BpfHdr 로 캐스팅하면 안 된다. 패딩 때문에 20 바이트인데 커널이 보내는 hdrlen 은 18 이라
// 실기기에서 모든 패킷이 오류도 로그도 없이 버려진다(실제로 한 번 겪었다).
const (
	bpfCapLenOffset = 8
	bpfHdrLenOffset = 16
	// bpfHdrFieldsLen 은 헤더 필드를 다 읽는 데 필요한 바이트다. 커널이 보고하는 최소 hdrlen 이기도 하다.
	bpfHdrFieldsLen = bpfHdrLenOffset + 2
)

// bpfWordAlign 은 다음 패킷이 시작하는 위치로 올림한다.
// macOS 의 BPF_ALIGNMENT 는 int32_t 크기인 4 다. 8 로 맞추면 패킷 경계가 어긋난다.
func bpfWordAlign(n int) int {
	const alignment = 4
	return (n + alignment - 1) &^ (alignment - 1)
}

// openBPFDevice 는 비어 있는 /dev/bpfN 을 하나 연다. 쓰이는 중인 번호는 EBUSY 라 건너뛴다.
func openBPFDevice() (int, error) {
	var lastErr error
	for i := range maxBPFDevices {
		path := fmt.Sprintf("/dev/bpf%d", i)
		fd, err := unix.Open(path, unix.O_RDONLY, 0)
		if err == nil {
			return fd, nil
		}
		if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
			// 권한 문제는 다음 번호에서도 똑같다. 계속 돌면 엉뚱한 오류로 끝난다.
			return -1, fmt.Errorf("%s 를 열 권한이 없다. 패킷 캡처는 root 로 실행해야 한다: %w", path, err)
		}
		lastErr = err
	}
	return -1, fmt.Errorf("쓸 수 있는 /dev/bpf 장치가 없다. 다른 프로그램이 전부 쓰고 있다: %w", lastErr)
}

// configureBPF 는 연 장치를 인터페이스에 붙이고 필터까지 건다. 순서가 중요하다.
func configureBPF(fd int, iface string, log *slog.Logger) error {
	// 버퍼 크기는 인터페이스에 붙기 전에만 바꿀 수 있다. 뒤로 가면 EINVAL 이다.
	// 실패해도 멈추지 않는다. 기본 버퍼로도 캡처 자체는 된다.
	if err := unix.IoctlSetPointerInt(fd, unix.BIOCSBLEN, captureBufferSize); err != nil {
		log.Warn("BPF 버퍼 크기를 못 키웠다. 기본 크기로 간다", "want", captureBufferSize, "err", err)
	}
	if err := setBPFInterface(fd, iface); err != nil {
		return err
	}

	// 필터가 이더넷 헤더를 전제로 오프셋을 잡았다. 아니면 조용히 0건이 되므로 여기서 멈춘다.
	dlt, err := unix.IoctlGetInt(fd, unix.BIOCGDLT)
	if err != nil {
		return fmt.Errorf("링크 종류를 못 읽었다: %w", err)
	}
	if dlt != unix.DLT_EN10MB {
		return fmt.Errorf("%s 는 이더넷이 아니다(DLT %d). 이 캡처는 이더넷 인터페이스만 다룬다", iface, dlt)
	}

	// 즉시 모드. 켜지 않으면 버퍼가 찰 때까지 read 가 돌아오지 않는다.
	if err := unix.IoctlSetPointerInt(fd, unix.BIOCIMMEDIATE, 1); err != nil {
		return fmt.Errorf("BPF 즉시 모드 설정 실패: %w", err)
	}
	if err := setBPFReadTimeout(fd, captureReadTimeout); err != nil {
		return err
	}
	if err := setBPFFilter(fd); err != nil {
		return err
	}

	// 필터를 걸기 전에 들어온 패킷이 버퍼에 남아 있다. 거르지 않은 것이라 버린다.
	if err := ioctlNoArg(fd, unix.BIOCFLUSH); err != nil {
		return fmt.Errorf("BPF 버퍼 비우기 실패: %w", err)
	}
	return nil
}

// bpfIfreq 는 BIOCSETIF 가 받는 struct ifreq 다. 뒤 16바이트는 크기를 맞추려고 둔 자리다.
type bpfIfreq struct {
	Name [unix.IFNAMSIZ]byte
	_    [16]byte
}

// setBPFInterface 는 장치를 인터페이스에 붙인다.
func setBPFInterface(fd int, iface string) error {
	if len(iface) >= unix.IFNAMSIZ {
		return fmt.Errorf("인터페이스 이름 %q 가 너무 길다", iface)
	}
	var ifr bpfIfreq
	copy(ifr.Name[:], iface)

	if err := ioctlPtr(fd, unix.BIOCSETIF, unsafe.Pointer(&ifr)); err != nil {
		return fmt.Errorf("%s 에 BPF 를 붙이지 못했다: %w", iface, err)
	}
	return nil
}

// setBPFReadTimeout 은 읽기 시한을 건다.
func setBPFReadTimeout(fd int, d time.Duration) error {
	tv := unix.Timeval{
		Sec:  int64(d / time.Second),
		Usec: int32((d % time.Second) / time.Microsecond),
	}
	if err := ioctlPtr(fd, unix.BIOCSRTIMEOUT, unsafe.Pointer(&tv)); err != nil {
		return fmt.Errorf("BPF 읽기 시한 설정 실패: %w", err)
	}
	return nil
}

// setBPFFilter 는 CaptureFilter 가 만든 프로그램을 커널에 건다.
func setBPFFilter(fd int) error {
	raw, err := CaptureFilter()
	if err != nil {
		return fmt.Errorf("BPF 필터를 만들지 못했다: %w", err)
	}

	// 지금은 같은 모양이지만 캐스팅하지 않는다. 어느 쪽이 바뀌면 커널이 쓰레기 프로그램을 받는다.
	insns := make([]unix.BpfInsn, len(raw))
	for i, r := range raw {
		insns[i] = unix.BpfInsn{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	prog := unix.BpfProgram{
		Len:   uint32(len(insns)),
		Insns: &insns[0],
	}

	err = ioctlPtr(fd, unix.BIOCSETF, unsafe.Pointer(&prog))
	// 커널이 명령을 복사해 갈 때까지 슬라이스가 살아 있어야 한다.
	runtime.KeepAlive(insns)
	if err != nil {
		return fmt.Errorf("BPF 필터를 걸지 못했다: %w", err)
	}
	return nil
}

// ioctlPtr 는 구조체 포인터를 넘기는 ioctl 이다. x/sys/unix 에 darwin 용 헬퍼가 없어 직접 부른다.
func ioctlPtr(fd int, req uint, arg unsafe.Pointer) error {
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg)); errno != 0 {
		return errno
	}
	return nil
}

// ioctlNoArg 는 인자가 없는 ioctl 이다.
func ioctlNoArg(fd int, req uint) error {
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), 0); errno != 0 {
		return errno
	}
	return nil
}

// defaultInterface 는 기본 라우트가 나가는 인터페이스 이름을 찾는다.
// UDP connect 는 패킷을 보내지 않고 라우팅 조회만 하므로 커널이 고른 로컬 주소를 읽는다.
func defaultInterface() (string, error) {
	conn, err := net.Dial("udp4", "203.0.113.1:53")
	if err != nil {
		return "", fmt.Errorf("기본 라우트를 찾지 못했다. 네트워크가 없는 것 같다: %w", err)
	}
	defer conn.Close()

	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return "", errors.New("로컬 주소를 읽지 못했다")
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("인터페이스 목록을 못 읽었다: %w", err)
	}
	for _, ifi := range ifaces {
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.Equal(local.IP) {
				return ifi.Name, nil
			}
		}
	}
	return "", fmt.Errorf("로컬 주소 %s 를 가진 인터페이스를 못 찾았다", local.IP)
}

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
