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
//
// netsnap_darwin.go 에도 비슷한 헬퍼가 있지만 합치지 않았다. 그쪽은 "지금 열린 연결 목록" 을
// 만들려고 원격 주소만 읽는데, 여기는 캡처한 흐름의 로컬 포트로 거꾸로 찾아야 해서 로컬 포트가
// 필요하다. 필드가 다르니 한 함수로 묶으면 양쪽 다 안 맞는 물건이 된다.
//
// union 접근을 C 에서 끝내는 이유는 cgo 가 union 을 바이트 배열로만 보여 주기 때문이다.
// Go 에서 오프셋을 손으로 계산하면 SDK 가 바뀌는 날 조용히 틀린 값을 읽는다.
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

	// vflag 가 IPv4/IPv6 를 알려 준다. AF_INET6 소켓이 v4 매핑 주소를 쥘 수 있어 family 보다
	// 이쪽이 정확하고, vflag 가 비어 오면 family 로 보정한다.
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

	// captureBufferSize 는 커널이 패킷을 모아 둘 버퍼 크기다.
	//
	// 기본값(debug.bpf_bufsize)은 4KB 라 2048바이트짜리 ClientHello 두 장이면 찬다. 그 뒤
	// 도착한 패킷은 커널이 그냥 버리고, 우리는 그런 일이 있었는지도 모른 채 도메인을 잃는다.
	// 512KB 는 macOS 기본 상한(debug.bpf_maxbufsize)이다. 더 요구해도 커널이 여기로 깎는다.
	captureBufferSize = 512 << 10

	// captureReadTimeout 은 읽기가 최대 얼마나 막혀 있을지다.
	//
	// 즉시 모드라 패킷이 오면 바로 돌아오지만, 트래픽이 없으면 read 가 영원히 잠든다.
	// 그 상태로는 Close 가 읽기 루프를 깨울 수 없다. 시한을 둬 주기적으로 깨어나게 한다.
	captureReadTimeout = 250 * time.Millisecond

	// capturePacketQueue 는 읽기 루프와 센서 사이의 큐 길이다.
	// 센서가 잠깐 밀려도 커널 버퍼까지 차기 전에 여기서 흡수한다.
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
		// 읽기 루프가 끝난 뒤에 fd 를 닫는다. 먼저 닫으면 그 번호가 다른 곳에 배정된 뒤
		// 루프가 남의 fd 를 읽는다. 읽기 시한이 있어 늦어도 captureReadTimeout 안에 끝난다.
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

// emit 은 프레임 하나를 채널로 넘긴다. 큐가 차면 버린다.
//
// 여기서 막으면 읽기 루프가 서고 커널 버퍼가 차서, 한 장 대신 수백 장을 한꺼번에 잃는다.
// 잃는 것을 줄일 수 없다면 적게 잃는 쪽을 고르고, 잃었다는 사실은 로그에 남긴다.
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
//
// BPF 는 패킷을 한 장씩 주지 않는다. 여러 장을 bpf_hdr 로 구분해 한 버퍼에 담아 준다.
// 첫 장만 읽고 말면 나머지를 전부 잃고, 다음 패킷 위치 계산을 틀리면 두 번째부터 헤더가
// 어긋나 전부 쓰레기가 된다. 이 함수가 이 파일에서 가장 틀리기 쉬운 곳이다.
func splitBPFBuffer(buf []byte, emit func([]byte)) {
	for off := 0; off+unix.SizeofBpfHdr <= len(buf); {
		hdr := (*unix.BpfHdr)(unsafe.Pointer(&buf[off]))
		hdrLen, capLen := int(hdr.Hdrlen), int(hdr.Caplen)

		start := off + hdrLen
		end := start + capLen
		if hdrLen < unix.SizeofBpfHdr || capLen < 0 || end > len(buf) {
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

// bpfWordAlign 은 다음 패킷이 시작하는 위치로 올림한다.
// macOS 의 BPF_ALIGNMENT 는 int32_t 크기인 4 다. 8 로 잘못 맞추면 패킷 경계가 어긋난다.
func bpfWordAlign(n int) int {
	const alignment = 4
	return (n + alignment - 1) &^ (alignment - 1)
}

// openBPFDevice 는 비어 있는 /dev/bpfN 을 하나 연다.
//
// BPF 장치는 한 프로세스가 하나씩 물고 쓴다. 이미 tcpdump 나 Wireshark 가 쓰고 있으면
// 그 번호는 EBUSY 라 다음 번호로 넘어간다.
func openBPFDevice() (int, error) {
	var lastErr error
	for i := range maxBPFDevices {
		path := fmt.Sprintf("/dev/bpf%d", i)
		fd, err := unix.Open(path, unix.O_RDONLY, 0)
		if err == nil {
			return fd, nil
		}
		if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
			// 권한 문제는 다음 번호에서도 똑같다. 여기서 끊지 않으면 256번 헛돌고 나서
			// "장치가 없다" 는 엉뚱한 오류를 낸다. 조용히 0건이 되는 것이 제일 나쁘다.
			return -1, fmt.Errorf("%s 를 열 권한이 없다. 패킷 캡처는 root 로 실행해야 한다: %w", path, err)
		}
		lastErr = err
	}
	return -1, fmt.Errorf("쓸 수 있는 /dev/bpf 장치가 없다. 다른 프로그램이 전부 쓰고 있다: %w", lastErr)
}

// configureBPF 는 연 장치를 인터페이스에 붙이고 필터까지 건다. 순서가 중요하다.
func configureBPF(fd int, iface string, log *slog.Logger) error {
	// 버퍼 크기는 인터페이스에 붙기 전에만 바꿀 수 있다. 뒤로 가면 EINVAL 이다.
	//
	// 실패해도 멈추지 않는다. 버퍼 크기는 패킷을 덜 잃기 위한 것이지 캡처가 되고 안 되고의
	// 문제가 아니다. 여기서 포기하면 기본 버퍼로라도 볼 수 있었던 것까지 못 본다.
	// 대신 실제 크기는 아래에서 BIOCGBLEN 으로 읽어 로그에 남기므로 조용히 넘어가지는 않는다.
	if err := unix.IoctlSetPointerInt(fd, unix.BIOCSBLEN, captureBufferSize); err != nil {
		log.Warn("BPF 버퍼 크기를 못 키웠다. 기본 크기로 간다", "want", captureBufferSize, "err", err)
	}
	if err := setBPFInterface(fd, iface); err != nil {
		return err
	}

	// 링크 종류를 확인한다. 우리 필터는 이더넷 헤더가 있다고 보고 오프셋을 잡았다.
	// utun 같은 인터페이스는 IP 헤더부터 주기 때문에 그대로 걸면 아무것도 안 잡힌다.
	// 조용히 0건이 되느니 여기서 이유를 말하고 멈춘다.
	dlt, err := unix.IoctlGetInt(fd, unix.BIOCGDLT)
	if err != nil {
		return fmt.Errorf("링크 종류를 못 읽었다: %w", err)
	}
	if dlt != unix.DLT_EN10MB {
		return fmt.Errorf("%s 는 이더넷이 아니다(DLT %d). 이 캡처는 이더넷 인터페이스만 다룬다", iface, dlt)
	}

	// 즉시 모드. 켜지 않으면 버퍼가 찰 때까지 read 가 돌아오지 않는다. 조용한 링크에서는
	// 몇 분씩 늦어져 실시간 탐지가 사실상 죽는다.
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

// bpfIfreq 는 BIOCSETIF 가 받는 struct ifreq 다.
// 뒤 16바이트는 주소 union 자리인데 BIOCSETIF 는 이름만 본다. 크기를 맞추려고 둔다.
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

	// bpf.RawInstruction 과 unix.BpfInsn 은 지금 같은 모양이지만, 그 사실에 기대 캐스팅하면
	// 어느 쪽이 바뀌는 날 커널이 쓰레기 프로그램을 받는다. 필드로 옮긴다.
	insns := make([]unix.BpfInsn, len(raw))
	for i, r := range raw {
		insns[i] = unix.BpfInsn{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	prog := unix.BpfProgram{
		Len:   uint32(len(insns)),
		Insns: &insns[0],
	}

	err = ioctlPtr(fd, unix.BIOCSETF, unsafe.Pointer(&prog))
	// 커널이 명령을 복사해 갈 때까지 슬라이스가 살아 있어야 한다. prog 안의 포인터만으로는
	// 컴파일러가 이 슬라이스를 살아 있다고 보지 않는다.
	runtime.KeepAlive(insns)
	if err != nil {
		return fmt.Errorf("BPF 필터를 걸지 못했다: %w", err)
	}
	return nil
}

// ioctlPtr 는 구조체 포인터를 넘기는 ioctl 이다.
// x/sys/unix 는 darwin 용으로 이런 범용 헬퍼를 내주지 않아 직접 부른다.
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
//
// UDP 소켓을 바깥 주소로 "연결" 해 보고 커널이 어떤 로컬 주소를 골랐는지 읽는다. UDP 의
// connect 는 패킷을 한 장도 보내지 않고 라우팅 테이블 조회만 한다. 라우팅 소켓 메시지를
// 직접 파싱하는 것보다 훨씬 짧고, 무엇이 기본 경로인지는 커널의 판단을 그대로 쓴다.
//
// 주소는 문서용으로 예약된 대역(TEST-NET-3)이라 실제로 누구의 것도 아니다.
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
	//
	// 스캔은 모든 프로세스의 fd 를 훑어 비싸다. 페이지 하나를 열면 ClientHello 가 수십 개
	// 몰려 오는데 그때마다 훑으면 그 순간 CPU 가 튄다. 한 번 훑은 결과로 그 무리를 다 덮는다.
	ownerCacheTTL = 500 * time.Millisecond

	// ownerRescanFloor 는 못 찾았을 때 다시 훑기까지의 최소 간격이다.
	//
	// 캐시에 없는 소켓은 스캔 뒤에 새로 열린 것일 수 있어서 다시 훑어야 찾는다. 그런데
	// 이미 닫힌 소켓은 몇 번을 훑어도 안 나오므로, 그런 조회가 몰리면 스캔만 반복한다.
	// 이 간격이 그 최악을 초당 몇 번으로 묶는다.
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
	// 원격 주소 표기가 어긋나는 경우가 있다. v4 매핑 IPv6 소켓이 "::ffff:1.2.3.4" 로 보이는 식이다.
	// 로컬 포트만으로도 지금 열린 소켓 중에서는 사실상 유일하므로 여기서 한 번 더 본다.
	return o.byPort[localPort]
}

// scanSocketOwners 는 지금 열린 TCP 소켓의 주인을 전부 모은다.
//
// PID 목록과 fd 목록을 읽는 헬퍼는 netsnap_darwin.go 에 이미 있어 그대로 쓴다.
// 권한이 없어 못 읽는 프로세스는 건너뛴다. 그것 때문에 스캔 전체를 버리면 볼 수 있는 것까지 못 본다.
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
