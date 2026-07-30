//go:build darwin

package sensor

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// bpfRecord 는 커널이 버퍼에 담는 모양대로 bpf_hdr + 프레임 한 장을 만든다.
// caplen 이 datalen 보다 작으면 스냅 길이에 잘린 패킷이다.
func bpfRecord(frame []byte, datalen int) []byte {
	hdr := make([]byte, unix.SizeofBpfHdr)
	binary.LittleEndian.PutUint32(hdr[0:], 1785400000) // tv_sec
	binary.LittleEndian.PutUint32(hdr[4:], 0)          // tv_usec
	binary.LittleEndian.PutUint32(hdr[8:], uint32(len(frame)))
	binary.LittleEndian.PutUint32(hdr[12:], uint32(datalen))
	binary.LittleEndian.PutUint16(hdr[16:], uint16(unix.SizeofBpfHdr))

	rec := append(hdr, frame...)
	// 다음 레코드는 4바이트 경계에서 시작한다.
	for len(rec)%4 != 0 {
		rec = append(rec, 0)
	}
	return rec
}

func TestSplitBPFBuffer(t *testing.T) {
	// 길이를 일부러 4의 배수가 아니게 섞는다. 정렬을 틀리면 두 번째부터 어긋난다.
	frames := [][]byte{
		bytes.Repeat([]byte{0xa1}, 61),
		bytes.Repeat([]byte{0xb2}, 14),
		bytes.Repeat([]byte{0xc3}, 100),
	}

	var buf []byte
	for _, f := range frames {
		buf = append(buf, bpfRecord(f, len(f))...)
	}

	var got [][]byte
	splitBPFBuffer(buf, func(frame []byte) { got = append(got, frame) })

	if len(got) != len(frames) {
		t.Fatalf("패킷 %d 장, 원하는 값 %d 장", len(got), len(frames))
	}
	for i := range frames {
		if !bytes.Equal(got[i], frames[i]) {
			t.Errorf("%d 번 패킷이 다르다: %d 바이트 %x...", i, len(got[i]), got[i][:min(8, len(got[i]))])
		}
	}
}

func TestSplitBPFBufferCopiesFrames(t *testing.T) {
	// 다음 read 가 같은 버퍼를 덮어쓴다. 복사하지 않고 넘기면 센서가 파싱하는 도중에 내용이 바뀐다.
	frame := bytes.Repeat([]byte{0x7f}, 32)
	buf := bpfRecord(frame, len(frame))

	var got []byte
	splitBPFBuffer(buf, func(f []byte) { got = f })
	if got == nil {
		t.Fatal("패킷이 안 나왔다")
	}

	for i := range buf {
		buf[i] = 0
	}
	if !bytes.Equal(got, frame) {
		t.Error("버퍼를 덮어쓰자 넘긴 패킷 내용도 바뀌었다")
	}
}

func TestSplitBPFBufferHandlesSnapped(t *testing.T) {
	// 스냅 길이에 잘린 패킷은 caplen 만큼만 있다. datalen 을 믿고 읽으면 버퍼 밖으로 나간다.
	frame := bytes.Repeat([]byte{0x55}, 40)
	buf := bpfRecord(frame, 1500)

	var got [][]byte
	splitBPFBuffer(buf, func(f []byte) { got = append(got, f) })
	if len(got) != 1 || len(got[0]) != 40 {
		t.Fatalf("패킷 %d 장, 첫 장 %d 바이트", len(got), len(got[0]))
	}
}

func TestSplitBPFBufferStopsOnGarbage(t *testing.T) {
	good := bytes.Repeat([]byte{0x11}, 24)
	tests := []struct {
		name string
		buf  []byte
		want int
	}{
		{name: "빈 버퍼", buf: nil, want: 0},
		{name: "헤더도 안 되는 길이", buf: make([]byte, unix.SizeofBpfHdr-1), want: 0},
		{
			name: "뒤가 잘린 버퍼는 앞의 온전한 것만 준다",
			want: 1,
			buf: append(bpfRecord(good, len(good)),
				bpfRecord(bytes.Repeat([]byte{0x22}, 40), 40)[:30]...),
		},
		{
			name: "caplen 이 버퍼보다 크면 멈춘다",
			want: 0,
			buf:  bpfRecord(good, len(good))[:unix.SizeofBpfHdr+4],
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := 0
			splitBPFBuffer(tt.buf, func([]byte) { n++ })
			if n != tt.want {
				t.Fatalf("패킷 %d 장, 원하는 값 %d 장", n, tt.want)
			}
		})
	}
}

// TestSplitBPFBufferRejectsShortHeaderLen 은 hdrlen 이 말이 안 되는 값일 때 멈추는지 본다.
// 여기서 안 멈추면 off 가 제자리를 돌아 무한 루프가 된다.
func TestSplitBPFBufferRejectsShortHeaderLen(t *testing.T) {
	buf := bpfRecord(bytes.Repeat([]byte{0x33}, 16), 16)
	binary.LittleEndian.PutUint16(buf[16:], 4) // hdrlen 을 헤더보다 작게 조작한다

	done := make(chan int, 1)
	go func() {
		n := 0
		splitBPFBuffer(buf, func([]byte) { n++ })
		done <- n
	}()

	select {
	case n := <-done:
		if n != 0 {
			t.Fatalf("깨진 헤더에서 패킷이 %d 장 나왔다", n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("무한 루프에 빠졌다")
	}
}

func TestBPFWordAlign(t *testing.T) {
	// macOS 의 BPF_ALIGNMENT 는 4 다. 8 로 맞추면 패킷 경계가 어긋난다.
	cases := map[int]int{0: 0, 1: 4, 3: 4, 4: 4, 5: 8, 20: 20, 81: 84}
	for in, want := range cases {
		if got := bpfWordAlign(in); got != want {
			t.Errorf("bpfWordAlign(%d) = %d, 원하는 값 %d", in, got, want)
		}
	}
}

// --- ProcOwner ---

// fakeClock 은 캐시 만료를 검사하려고 시간을 손으로 민다.
type fakeClock struct{ at time.Time }

func (c *fakeClock) now() time.Time      { return c.at }
func (c *fakeClock) add(d time.Duration) { c.at = c.at.Add(d) }

// countingScan 은 몇 번 훑였는지 세고 정해 둔 표를 돌려준다.
type countingScan struct {
	calls  int
	exact  map[ownerKey]string
	byPort map[int]string
}

func (s *countingScan) scan() (map[ownerKey]string, map[int]string) {
	s.calls++
	return s.exact, s.byPort
}

func newTestOwner(scan *countingScan, clock *fakeClock) *ProcOwner {
	return &ProcOwner{scan: scan.scan, now: clock.now}
}

func TestProcOwnerSharesScanAcrossBurst(t *testing.T) {
	// 페이지 하나를 열면 ClientHello 가 몰려 온다. 그때마다 훑으면 그 순간 CPU 가 튄다.
	clock := &fakeClock{at: time.Unix(1785400000, 0)}
	scan := &countingScan{
		exact: map[ownerKey]string{
			{51000, "93.184.216.34", 443}: "/Applications/Firefox.app/Contents/MacOS/firefox",
			{51001, "93.184.216.34", 443}: "/Applications/Firefox.app/Contents/MacOS/firefox",
		},
		byPort: map[int]string{51000: "x", 51001: "x"},
	}
	o := newTestOwner(scan, clock)

	for _, port := range []int{51000, 51001, 51000} {
		if got := o.Lookup(port, "93.184.216.34", 443); got == "" {
			t.Fatalf("포트 %d 의 주인을 못 찾았다", port)
		}
		clock.add(10 * time.Millisecond)
	}
	if scan.calls != 1 {
		t.Errorf("스캔 %d 회, 버스트 전체가 한 번을 나눠 써야 한다", scan.calls)
	}
}

func TestProcOwnerRescansAfterTTL(t *testing.T) {
	// 캐시가 오래되면 방금 열린 소켓을 못 찾는다. 500ms 를 넘기면 다시 훑어야 한다.
	clock := &fakeClock{at: time.Unix(1785400000, 0)}
	scan := &countingScan{
		exact:  map[ownerKey]string{{51000, "1.2.3.4", 443}: "/usr/bin/curl"},
		byPort: map[int]string{51000: "/usr/bin/curl"},
	}
	o := newTestOwner(scan, clock)

	o.Lookup(51000, "1.2.3.4", 443)
	clock.add(ownerCacheTTL + time.Millisecond)
	if got := o.Lookup(51000, "1.2.3.4", 443); got != "/usr/bin/curl" {
		t.Fatalf("주인 = %q", got)
	}
	if scan.calls != 2 {
		t.Errorf("스캔 %d 회, TTL 이 지났으니 2회여야 한다", scan.calls)
	}
}

func TestProcOwnerRescansOnMiss(t *testing.T) {
	// ClientHello 를 본 소켓은 그 순간 확실히 열려 있다. 캐시에 없으면 스캔 뒤에 열린 것이라
	// 다시 훑어야 찾는다. 여기서 포기하면 새 연결의 프로세스를 거의 다 잃는다.
	clock := &fakeClock{at: time.Unix(1785400000, 0)}
	scan := &countingScan{exact: map[ownerKey]string{}, byPort: map[int]string{}}
	o := newTestOwner(scan, clock)

	if got := o.Lookup(51000, "1.2.3.4", 443); got != "" {
		t.Fatalf("주인 = %q, 아직 없어야 한다", got)
	}

	// 그 사이 소켓이 열렸다.
	scan.exact = map[ownerKey]string{{51000, "1.2.3.4", 443}: "/usr/bin/curl"}
	clock.add(ownerRescanFloor)

	if got := o.Lookup(51000, "1.2.3.4", 443); got != "/usr/bin/curl" {
		t.Fatalf("주인 = %q", got)
	}
	if scan.calls != 2 {
		t.Errorf("스캔 %d 회, 2회여야 한다", scan.calls)
	}
}

func TestProcOwnerThrottlesMissRescan(t *testing.T) {
	// 이미 닫힌 소켓은 몇 번을 훑어도 안 나온다. 그런 조회가 몰릴 때 스캔만 반복하면 안 된다.
	clock := &fakeClock{at: time.Unix(1785400000, 0)}
	scan := &countingScan{exact: map[ownerKey]string{}, byPort: map[int]string{}}
	o := newTestOwner(scan, clock)

	for range 20 {
		o.Lookup(51000, "1.2.3.4", 443)
		clock.add(time.Millisecond)
	}
	if scan.calls > 1 {
		t.Errorf("스캔 %d 회, 최소 간격 안에서는 1회여야 한다", scan.calls)
	}
}

func TestProcOwnerFallsBackToLocalPort(t *testing.T) {
	// 소켓이 v4 매핑 IPv6 이면 원격 주소 표기가 패킷 쪽과 어긋난다. 그때도 로컬 포트로 찾는다.
	clock := &fakeClock{at: time.Unix(1785400000, 0)}
	scan := &countingScan{
		exact:  map[ownerKey]string{{51000, "::ffff:93.184.216.34", 443}: "/usr/bin/curl"},
		byPort: map[int]string{51000: "/usr/bin/curl"},
	}
	o := newTestOwner(scan, clock)

	if got := o.Lookup(51000, "93.184.216.34", 443); got != "/usr/bin/curl" {
		t.Fatalf("주인 = %q", got)
	}
}

// TestDefaultInterface 는 기본 라우트의 인터페이스를 실제로 찾아 본다.
// 캡처가 붙을 곳을 잘못 고르면 조용히 0건이 되므로 개발 기기에서라도 확인해 둔다.
func TestDefaultInterface(t *testing.T) {
	name, err := defaultInterface()
	if err != nil {
		t.Skipf("기본 라우트가 없다. 네트워크 없는 환경으로 보고 건너뛴다: %v", err)
	}
	if _, err := net.InterfaceByName(name); err != nil {
		t.Fatalf("%q 는 존재하는 인터페이스가 아니다: %v", name, err)
	}
	t.Logf("기본 인터페이스 = %s", name)
}

// kernelBpfRecord 는 실기기 macOS 커널이 담는 그대로 레코드를 만든다.
//
// bpfRecord 와 다른 점은 bh_hdrlen 하나뿐인데 그게 핵심이다. 커널은
// offsetof(bh_hdrlen) + sizeof(bh_hdrlen) = 18 을 보낸다. Go 의 unix.BpfHdr 은 뒤에 패딩이
// 붙어 20 이다. 이 둘을 견주는 코드를 두면 실기기에서 모든 패킷이 버려지는데, 픽스처를 20 으로
// 만들면 그 사실이 테스트에 안 드러난다. 실제로 그렇게 통과해 놓고 현장에서 0 건이 났다.
func kernelBpfRecord(frame []byte) []byte {
	const kernelHdrLen = 18 // 커널이 보고하는 값

	hdr := make([]byte, unix.SizeofBpfHdr)
	binary.LittleEndian.PutUint32(hdr[0:], 1785400000)
	binary.LittleEndian.PutUint32(hdr[4:], 0)
	binary.LittleEndian.PutUint32(hdr[8:], uint32(len(frame)))
	binary.LittleEndian.PutUint32(hdr[12:], uint32(len(frame)))
	binary.LittleEndian.PutUint16(hdr[16:], kernelHdrLen)

	// 커널은 bh_hdrlen 뒤부터 곧바로 프레임을 놓는다. 여기서도 18 바이트만 헤더로 쓴다.
	rec := append(hdr[:kernelHdrLen], frame...)
	for len(rec)%4 != 0 {
		rec = append(rec, 0)
	}
	return rec
}

// 실기기 커널이 보내는 헤더 길이로도 패킷이 나와야 한다.
func TestSplitBPFBufferAcceptsKernelHeaderLen(t *testing.T) {
	frames := [][]byte{
		[]byte("first-frame-payload"),
		[]byte("second"),
		[]byte("third-one-longer-than-the-others"),
	}
	var buf []byte
	for _, f := range frames {
		buf = append(buf, kernelBpfRecord(f)...)
	}

	var got [][]byte
	splitBPFBuffer(buf, func(f []byte) { got = append(got, f) })

	if len(got) != len(frames) {
		t.Fatalf("프레임 %d 장이 나왔다. want %d. 커널이 보고하는 bh_hdrlen(18)을 거부하고 있다", len(got), len(frames))
	}
	for i := range frames {
		if string(got[i]) != string(frames[i]) {
			t.Errorf("[%d] = %q, want %q", i, got[i], frames[i])
		}
	}
}
