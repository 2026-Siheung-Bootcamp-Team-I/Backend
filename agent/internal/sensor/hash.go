package sensor

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"sync"
	"sync/atomic"
)

// 이 파일에는 빌드 태그가 없다. 파일을 읽어 sha256 을 구하는 일은 플랫폼과 무관하고,
// 비용을 막는 규칙(크기 상한, 캐시)이야말로 개발 기기에서 검증되어야 하는 부분이다.

const (
	// hashMaxBytes 는 해시를 뜰 파일 크기의 상한이다.
	//
	// 상한이 필요한 이유는 이 함수가 프로세스 실행마다 불리기 때문이다. 상한이 없으면 몇 GB 짜리
	// 실행 파일 하나가 뜰 때마다 디스크를 그만큼 읽고 CPU 를 통째로 쓴다. 관측하려고 띄운
	// 에이전트가 관측 대상 기기를 느리게 만드는 것은 본말이 뒤집힌 것이다.
	//
	// 32MB 로 잡은 근거는 실제 실행 파일 크기다. macOS 의 /usr/bin 과 Windows 의 System32 에
	// 있는 것은 대개 수백 KB 에서 수 MB 이고, 유니버설 바이너리나 전자 문서 앱처럼 큰 것도
	// 수십 MB 안쪽이다. 그보다 큰 파일은 데이터나 컨테이너 이미지지 우리가 해시로 조회할
	// 실행 파일이 아니다. SSD 기준 32MB 읽기와 해시는 수십 밀리초라 프로세스 실행마다 물어도
	// 감당된다.
	hashMaxBytes int64 = 32 << 20

	// hashCacheMax 는 캐시 항목 수 상한이다. 넘으면 통째로 비운다.
	//
	// 오래 도는 에이전트에서 맵이 무한정 커지는 것만 막으면 되므로 정교한 축출은 필요 없다.
	// 비워도 다음 실행에서 다시 채워질 뿐이고, 한 기기에서 실제로 도는 실행 파일 종류는
	// 수백 개 수준이라 4096 이면 평소에는 비울 일이 없다. pidCache 와 같은 방식이다.
	hashCacheMax = 4096
)

// HashStats 는 해시 계산이 실제로 얼마나 먹히고 있는지 보여 준다.
//
// 실패를 세는 이유가 중요하다. 해시를 못 구하면 조용히 빈 값이 되는데, 그 상태는 "해시가
// 필요 없는 이벤트" 와 서버에서 구분되지 않는다. 세어 두면 "전부 비어 있다" 는 상태의 원인이
// 권한 문제인지 크기 상한인지 로그만 보고 가릴 수 있다.
type HashStats struct {
	Hashed uint64 // 파일을 읽어 해시를 구한 횟수
	Cached uint64 // 캐시로 답한 횟수
	Failed uint64 // 읽지 못해 빈 값을 준 횟수(권한 없음, 이미 지워짐, 파일이 아님)
	TooBig uint64 // 크기 상한을 넘겨 건너뛴 횟수
}

// hashKey 는 같은 내용인지 가르는 기준이다.
//
// 경로만으로는 안 된다. 같은 이름으로 덮어쓴 파일이 예전 해시를 달고 올라가면 그건 없는 것보다
// 나쁘다. 크기와 수정시각까지 같으면 같은 내용으로 본다. 내용을 바꾸면서 크기와 수정시각을
// 그대로 유지하는 것은 일부러 시각을 되돌려야 가능한 일이고, 그렇게까지 하는 상대를 막으려면
// 캐시를 통째로 없애야 하는데 그 비용은 이득보다 크다.
type hashKey struct {
	path string
	size int64
	mod  int64 // 수정시각, UnixNano
}

// FileHasher 는 파일의 sha256 을 구한다. 결과를 캐시한다.
//
// 센서 여러 개가 같은 것을 나눠 쓰므로 동시 호출에 안전하다.
type FileHasher struct {
	mu    sync.Mutex
	cache map[hashKey]string

	// 상한은 필드로 둔다. 테스트에서 몇 GB 짜리 파일을 만들지 않고 규칙만 확인하기 위해서다.
	maxBytes   int64
	maxEntries int

	hashed atomic.Uint64
	cached atomic.Uint64
	failed atomic.Uint64
	tooBig atomic.Uint64
}

// NewFileHasher 는 기본 상한을 쓰는 해시기를 만든다.
func NewFileHasher() *FileHasher {
	return &FileHasher{
		cache:      make(map[hashKey]string),
		maxBytes:   hashMaxBytes,
		maxEntries: hashCacheMax,
	}
}

// Hash 는 파일의 sha256 을 소문자 16진수로 준다. 못 구하면 빈 문자열이다.
//
// 못 구하는 것을 오류로 올리지 않는 이유는 그것이 정상 상황이기 때문이다. 짧게 살다 죽는
// 프로세스의 이미지는 이미 지워져 있고, 권한이 모자란 경로도 있다. 해시 하나 때문에 실행
// 사실 자체를 잃는 쪽이 훨씬 나쁘다.
//
// nil 리시버를 받아 준다. 해시를 붙이지 않는 센서가 nil 을 그대로 넘길 수 있게 해서
// 호출부마다 nil 검사를 적지 않게 한다.
func (h *FileHasher) Hash(path string) string {
	if h == nil || path == "" {
		return ""
	}

	// 먼저 stat 을 본다. 크기 상한과 캐시 키가 둘 다 여기서 나온다.
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		// 심볼릭 링크는 Stat 이 따라가므로 여기서 걸리지 않는다.
		// 디렉터리나 장치 파일은 해시할 대상이 아니다.
		h.failed.Add(1)
		return ""
	}
	if info.Size() > h.maxBytes {
		h.tooBig.Add(1)
		return ""
	}

	key := hashKey{path: path, size: info.Size(), mod: info.ModTime().UnixNano()}
	if sum, ok := h.lookup(key); ok {
		h.cached.Add(1)
		return sum
	}

	sum, err := hashFile(path, h.maxBytes)
	if err != nil {
		h.failed.Add(1)
		return ""
	}
	h.hashed.Add(1)
	h.store(key, sum)
	return sum
}

// Stats 는 지금까지의 집계를 준다.
func (h *FileHasher) Stats() HashStats {
	if h == nil {
		return HashStats{}
	}
	return HashStats{
		Hashed: h.hashed.Load(),
		Cached: h.cached.Load(),
		Failed: h.failed.Load(),
		TooBig: h.tooBig.Load(),
	}
}

func (h *FileHasher) lookup(key hashKey) (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	sum, ok := h.cache[key]
	return sum, ok
}

func (h *FileHasher) store(key hashKey, sum string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cache == nil || len(h.cache) >= h.maxEntries {
		h.cache = make(map[hashKey]string, h.maxEntries)
	}
	h.cache[key] = sum
}

// size 는 캐시가 쥐고 있는 항목 수다. 맵이 새는지 확인하는 용도다.
func (h *FileHasher) size() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.cache)
}

// hashFile 은 파일을 읽어 sha256 을 구한다.
//
// 읽기에도 상한을 다시 건다. stat 과 open 사이에 파일이 커질 수 있는데, 그때 끝까지 읽으면
// 상한을 둔 의미가 없다. 상한을 넘겨 읽히면 오류로 본다. 앞부분만의 해시를 돌려주면 그건
// 틀린 값이고, 틀린 해시는 없는 것보다 나쁘다.
func hashFile(path string, maxBytes int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	sum := sha256.New()
	n, err := io.Copy(sum, io.LimitReader(f, maxBytes+1))
	if err != nil {
		return "", err
	}
	if n > maxBytes {
		return "", os.ErrInvalid
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}
