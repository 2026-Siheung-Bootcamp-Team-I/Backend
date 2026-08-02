//go:build windows

package sensor

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

// 이 파일은 pktmon 캡처를 켜고 끄는 배선이다. 판정에 관여하는 것은 전부 pktmon.go 에 있다.
// pktmon.exe 호출을 없애지 마라. 프로바이더만 켜면 pktmon.sys 가 안 돌아 이벤트가 0건이 된다.

// pktMonExe 는 실행할 파일 이름이다. PATH 에서 찾는다.
const pktMonExe = "pktmon.exe"

// pktMonQueue 는 ETW 콜백과 센서 사이의 큐 길이다. macOS 캡처의 큐와 같은 크기다.
// 줄이면 콜백 스레드가 막히고 커널 버퍼가 차서 이벤트를 한꺼번에 잃는다.
const pktMonQueue = 2048

// PktMonCapture 는 pktmon 이 올려 주는 프레임을 채널로 흘린다. PacketSource 를 만족한다.
// 세션은 ETWSensor 가 하나만 열고, 이벤트 160 을 이 타입의 deliver 에 넘긴다.
type PktMonCapture struct {
	log     *slog.Logger
	exe     string
	etlPath string

	packets chan []byte

	// mu 는 채널 닫기와 넣기를 갈라 놓는다. 없으면 닫힌 채널에 넣다가 panic 이 난다.
	mu   sync.Mutex
	done bool

	stats pktMonStats
}

// OpenPktMonCapture 는 커널 필터를 걸고 pktmon 캡처를 시작한다.
// 여기서 실패하면 호출자가 L7 센서만 건너뛴다.
func OpenPktMonCapture(log *slog.Logger) (*PktMonCapture, error) {
	if log == nil {
		log = slog.Default()
	}

	exe, err := exec.LookPath(pktMonExe)
	if err != nil {
		return nil, fmt.Errorf("%s 를 찾지 못했다. Windows 10 2004 이상이어야 인박스로 들어 있다: %w", pktMonExe, err)
	}

	c := &PktMonCapture{
		log:     log,
		exe:     exe,
		etlPath: filepath.Join(os.TempDir(), "edrdog-pktmon.etl"),
		packets: make(chan []byte, pktMonQueue),
	}

	// 필터 목록은 시스템 전체에 하나뿐이다. 남은 것을 두면 우리가 걸지 않은 조건으로 패킷이 올라온다.
	if err := c.run("filter", "remove"); err != nil {
		return nil, err
	}
	// 하나라도 실패하면 전부 치운다. 반만 걸린 상태는 왜 그런지 로그만 봐서는 알 수 없다.
	for _, port := range []int{portHTTPS, portHTTP} {
		if err := c.run(pktMonFilterArgs(port)...); err != nil {
			c.runQuietly("filter", "remove")
			return nil, err
		}
	}
	if err := c.run(pktMonStartArgs(CaptureSnapLen, c.etlPath)...); err != nil {
		// 필터만 남기고 나가지 않는다. 우리가 건 필터는 우리가 치운다.
		c.runQuietly("filter", "remove")
		return nil, err
	}

	log.Info("pktmon 캡처를 시작했다",
		// 포트를 둘 다 적어야 0 건일 때 필터 탓인지 트래픽 탓인지 가릴 수 있다.
		"filter", pktMonFilterName, "ports", []int{portHTTPS, portHTTP},
		"pktSize", CaptureSnapLen, "etl", c.etlPath)
	return c, nil
}

// Packets 는 캡처한 프레임을 준다.
func (c *PktMonCapture) Packets() <-chan []byte { return c.packets }

// Close 는 캡처를 멈추고 걸어 둔 필터를 치운다.
// L7Sensor 와 ETWSensor 가 둘 다 부른다. 멱등성을 깨면 닫힌 채널을 두 번 닫아 panic 이 난다.
func (c *PktMonCapture) Close() error {
	c.mu.Lock()
	first := !c.done
	c.done = true
	if first {
		close(c.packets)
	}
	c.mu.Unlock()

	if !first {
		return nil
	}

	c.log.Info("pktmon 캡처를 닫는다", c.stats.logArgs()...)

	// 하나가 실패해도 나머지는 시도한다. 필터를 남긴 채 나가면 다음 실행이 그걸 물려받는다.
	var errs []string
	if err := c.run("stop"); err != nil {
		errs = append(errs, err.Error())
	}
	if err := c.run("filter", "remove"); err != nil {
		errs = append(errs, err.Error())
	}
	// pktmon 은 로그 대상 없이 시작할 수 없어서 만들어진 파일이다. 우리는 읽지 않으므로 지운다.
	if err := os.Remove(c.etlPath); err != nil && !os.IsNotExist(err) {
		errs = append(errs, fmt.Sprintf("%s 를 지우지 못했다: %v", c.etlPath, err))
	}

	// pktmon.sys 는 내리지 않는다. 드라이버는 시스템 전체가 공유한다.
	if len(errs) > 0 {
		return fmt.Errorf("pktmon 정리 중 오류: %s", strings.Join(errs, "; "))
	}
	return nil
}

// deliver 는 ETW 이벤트 160 하나를 프레임으로 바꿔 채널에 넣는다.
// 복사를 빼면 센서가 읽을 때쯤 다른 패킷의 바이트가 들어 있다.
// 어떤 경우에도 블로킹하지 않는다. 여기서 막히면 트레이스가 멈추고 커널 버퍼가 통째로 넘친다.
func (c *PktMonCapture) deliver(userData []byte) {
	frame, reject := parsePktMonPacket(userData)
	if reject != pktMonAccept {
		c.stats.count(reject)
		return
	}
	c.stats.observe(frame)

	ethernet, reject := pktMonEthernetFrame(frame)
	if reject != pktMonAccept {
		c.stats.count(reject)
		return
	}

	// 들어오는 쪽은 살릴 것만 남긴다. HTTP 응답은 상태 코드가 필요하고 TLS 는 아니다.
	if pktMonInbound(frame.DirTag) && !pktMonKeepInbound(ethernet) {
		c.stats.count(pktMonRejectInbound)
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done {
		return
	}
	select {
	case c.packets <- ethernet:
		c.stats.count(pktMonAccept)
	default:
		// 큐가 찼다. 여기서 기다리면 한 장 대신 수백 장을 잃는다.
		c.stats.count(pktMonRejectQueueFull)
	}
}

// ReportHealth 는 지금까지 본 프레임을 이유별로 로그에 남긴다.
// 이 로그가 없으면 accept 0건일 때 어디서 끊겼는지 실기기에서 가릴 방법이 없다.
func (c *PktMonCapture) ReportHealth() {
	args := c.stats.logArgs()
	if c.stats.counts[pktMonAccept].Load() == 0 {
		c.log.Warn("pktmon 프레임을 한 건도 넘기지 못했다", args...)
		return
	}
	c.log.Info("pktmon 캡처 상태", args...)
}

// run 은 pktmon 을 한 번 부르고 결과를 본다.
// 출력을 오류에 담는다. 종료 코드만 보면 권한 부족 같은 실패 이유 설명을 통째로 잃는다.
func (c *PktMonCapture) run(args ...string) error {
	cmd := exec.Command(c.exe, args...)
	// 콘솔에서 돌 때 창이 깜빡이지 않게 한다.
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pktmon %s 가 실패했다(%v): %s",
			strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return nil
}

// runQuietly 는 정리 경로에서 쓴다. 이미 다른 오류를 들고 나가는 중이라 결과를 로그로만 남긴다.
func (c *PktMonCapture) runQuietly(args ...string) {
	if err := c.run(args...); err != nil {
		c.log.Warn("pktmon 정리 명령이 실패했다", "err", err)
	}
}
