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
//
// # 드라이버를 설치하지 않는다
//
// Npcap 은 라이선스가 재배포를 금지해 쓸 수 없다. pktmon 은 Windows 10 2004 이후와
// Windows 11 에 인박스로 들어 있는 캡처 컴포넌트라 설치할 것이 없다.
//
// # ETW 프로바이더를 켜는 것만으로는 캡처가 시작되지 않는다
//
// pktmon.sys 가 먼저 시작돼야 이벤트를 만들기 시작한다. 프로바이더만 켜면 세션도 붙고
// 오류도 없는데 이벤트가 한 건도 오지 않는다. 이 저장소가 가장 무서워하는 실패 모양이다.
//
// 드라이버를 시작하는 방법은 셋이다.
//
//  1. 문서화된 Win32 API(PacketMonitorCreateLiveSession 등, Pktmonapi.dll). 이게 제일 좋아
//     보이지만 MS 문서의 요구 사항 표에 "Minimum supported client" 가 비어 있고 서버는
//     Windows Server 2022 6b 업데이트 이상이라고만 적혀 있다. 우리 대상은 Windows 10/11
//     클라이언트라 이 API 가 그 위에 있다는 근거가 없다.
//  2. Pktmonapi.dll 의 옛 export(PktmonStart, PktmonAddFilter 등)나 \\.\PktMonDev 로 보내는
//     IOCTL. 둘 다 문서가 없다. 인자 구조를 리버스 엔지니어링 글에서 짐작해 넣는 셈인데,
//     틀려도 오류가 아니라 조용한 0건으로 나타난다. 이번 작업에서 가장 피해야 할 종류의 위험이다.
//  3. pktmon.exe 를 부른다. 인자와 동작이 MS 문서에 그대로 적혀 있고 판이 바뀌어도 유지된다.
//
// 외부 프로세스를 띄우는 것이 마지막 수단이라는 원칙에는 동의하지만, 남은 둘이 "문서가 없어
// 틀렸는지도 모르는 채 0건" 으로 끝날 수 있는 길이라 3번을 골랐다. 부르는 것은 시작과 끝
// 각각 두 번뿐이고, 이벤트는 우리 ETW 세션에서 직접 받는다. 즉 데이터 경로에는 외부
// 프로세스가 없다.

// pktMonExe 는 실행할 파일 이름이다. PATH 에서 찾는다.
const pktMonExe = "pktmon.exe"

// pktMonQueue 는 ETW 콜백과 센서 사이의 큐 길이다.
//
// 센서가 잠깐 밀려도 여기서 흡수한다. ETW 콜백 스레드가 막히면 커널 버퍼가 차서 이벤트를
// 한꺼번에 잃기 때문에, 그 앞에 여유를 두는 것이 중요하다. macOS 캡처의 큐와 같은 크기다.
const pktMonQueue = 2048

// PktMonCapture 는 pktmon 이 올려 주는 프레임을 채널로 흘린다. PacketSource 를 만족한다.
//
// 이벤트를 받는 것은 이 타입이 아니다. ETW 세션은 ETWSensor 가 하나만 열고, 거기로 올라온
// 이벤트 160 을 이 타입의 deliver 에 넘긴다. 세션을 따로 열지 않는 이유는 프로바이더 주석에 적었다.
type PktMonCapture struct {
	log     *slog.Logger
	exe     string
	etlPath string

	packets chan []byte

	// mu 는 채널 닫기와 넣기를 갈라 놓는다. deliver 는 ETW 콜백 스레드에서 불리고 Close 는
	// 센서 고루틴에서 불리는데, 잠그지 않으면 닫힌 채널에 넣다가 panic 이 난다.
	mu   sync.Mutex
	done bool

	stats pktMonStats
}

// OpenPktMonCapture 는 커널 필터를 걸고 pktmon 캡처를 시작한다.
//
// 여기서 실패하면 호출자가 L7 센서만 건너뛴다. 캡처가 없어도 나머지 센서는 멀쩡하다.
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

	// 남아 있던 필터를 먼저 지운다. 필터는 시스템 전체에 하나뿐인 목록이라, 앞서 죽은
	// 우리 프로세스나 다른 도구가 남긴 것이 그대로 살아 있을 수 있다. 그걸 두고 시작하면
	// 우리가 걸지 않은 조건으로 패킷이 올라온다. 특히 포트 53 필터가 남아 있으면 Windows
	// 에서는 ETW 로 이미 받고 있는 DNS 를 패킷에서 한 번 더 뽑아 같은 질의가 두 번 올라간다.
	if err := c.run("filter", "remove"); err != nil {
		return nil, err
	}
	// 포트마다 필터를 따로 건다. 하나라도 실패하면 우리가 건 것을 치우고 나간다.
	// 반만 걸린 채로 두면 TLS 는 잡히고 HTTP 는 안 잡히는 상태가 되는데, 그게 왜 그런지
	// 로그만 봐서는 알 수 없다.
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
		// 포트를 둘 다 적는다. 하나만 적으면 HTTP 가 0 건일 때 필터를 안 건 것인지
		// 트래픽이 없었던 것인지 로그로 가릴 수 없다.
		"filter", pktMonFilterName, "ports", []int{portHTTPS, portHTTP},
		"pktSize", CaptureSnapLen, "etl", c.etlPath)
	return c, nil
}

// Packets 는 캡처한 프레임을 준다.
func (c *PktMonCapture) Packets() <-chan []byte { return c.packets }

// Close 는 캡처를 멈추고 걸어 둔 필터를 치운다.
//
// 두 번 불려도 안전하다. L7Sensor 가 끝날 때 한 번 부르고, ETW 세션이 먼저 죽으면
// ETWSensor 도 부른다. 어느 쪽이 먼저든 정리는 한 번만 일어나야 한다.
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

	// pktmon.sys 는 내리지 않는다(pktmon unload). 드라이버는 시스템 전체가 공유하는 것이라
	// 다른 도구가 쓰고 있을 수 있고, 남겨 두어도 캡처가 멈춘 상태에서는 아무것도 하지 않는다.
	if len(errs) > 0 {
		return fmt.Errorf("pktmon 정리 중 오류: %s", strings.Join(errs, "; "))
	}
	return nil
}

// deliver 는 ETW 이벤트 160 하나를 프레임으로 바꿔 채널에 넣는다.
//
// userData 는 이 함수가 돌아간 뒤 재사용될 수 있는 버퍼로 본다. ETW 콜백이 주는 것이
// 원래 그런 버퍼이기 때문이다. 그래서 채널로 나가는 것은 pktMonEthernetFrame 이 복사한
// 것뿐이다. 그 복사를 빼면 센서가 읽을 때쯤 다른 패킷의 바이트가 들어 있게 된다.
//
// 이 함수는 ETW 콜백 스레드에서 불린다. 여기서 막히면 트레이스 전체가 멈추고 커널 버퍼가
// 차서 이벤트를 통째로 잃는다. 그래서 어떤 경우에도 블로킹하지 않는다.
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

	// 들어오는 쪽은 살릴 것만 남긴다. TLS 는 SNI 가 나가는 ClientHello 에만 있어서
	// 들어오는 443 을 다 넘기면 하는 일 없이 CPU 만 쓴다. HTTP 응답은 상태 코드가 필요하다.
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
		// 큐가 찼다. 여기서 기다리면 한 장 대신 수백 장을 잃는다. macOS 캡처와 같은 판단이다.
		c.stats.count(pktMonRejectQueueFull)
	}
}

// ReportHealth 는 지금까지 본 프레임을 이유별로 로그에 남긴다.
//
// accept 가 0 인데 다른 이유가 쌓여 있으면 어디서 끊겼는지가 바로 보인다. sizeMismatch 가
// 쌓이면 우리가 읽는 필드 위치가 이 Windows 판과 어긋난 것이고, empty 가 쌓이면 keyword
// 0x10 이 안 걸린 것이며, linkType 이 쌓이면 이더넷도 raw IP 도 아닌 프레임이 오는 것이다.
func (c *PktMonCapture) ReportHealth() {
	args := c.stats.logArgs()
	if c.stats.counts[pktMonAccept].Load() == 0 {
		c.log.Warn("pktmon 프레임을 한 건도 넘기지 못했다", args...)
		return
	}
	c.log.Info("pktmon 캡처 상태", args...)
}

// run 은 pktmon 을 한 번 부르고 결과를 본다.
//
// 출력을 오류 메시지에 담는 이유는, 관리자 권한이 없거나 다른 캡처가 이미 돌고 있을 때
// pktmon 이 그 이유를 stdout 으로 말해 주기 때문이다. 종료 코드만 보면 그 설명을 잃는다.
func (c *PktMonCapture) run(args ...string) error {
	cmd := exec.Command(c.exe, args...)
	// 서비스로 돌 때는 창이 뜨지 않지만 콘솔에서 돌 때는 뜬다. 관측용 에이전트가 사용자
	// 화면에 창을 깜빡이게 할 이유가 없다.
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
