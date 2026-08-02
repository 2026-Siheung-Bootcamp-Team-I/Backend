package sensor

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"sync"
	"sync/atomic"
)

const (
	// hashMaxBytes 는 해시를 뜰 파일 크기의 상한이다.
	// 상한을 풀면 몇 GB 짜리 실행 파일이 뜰 때마다 그만큼 디스크를 읽고 CPU 를 쓴다.
	hashMaxBytes int64 = 32 << 20

	// hashCacheMax 는 캐시 항목 수 상한이다. 넘으면 통째로 비운다.
	// 상한을 풀면 오래 도는 에이전트에서 맵이 무한정 커진다.
	hashCacheMax = 4096
)

// HashStats 는 해시 계산이 실제로 얼마나 먹히고 있는지 보여 준다.
// 실패를 세지 않으면 해시가 전부 빈 상태의 원인이 권한인지 크기 상한인지 가릴 수 없다.
type HashStats struct {
	Hashed uint64 // 파일을 읽어 해시를 구한 횟수
	Cached uint64 // 캐시로 답한 횟수
	Failed uint64 // 읽지 못해 빈 값을 준 횟수(권한 없음, 이미 지워짐, 파일이 아님)
	TooBig uint64 // 크기 상한을 넘겨 건너뛴 횟수
}

// hashKey 는 같은 내용인지 가르는 기준이다.
// 크기와 수정시각을 빼면 덮어쓴 파일이 예전 해시를 달고 올라간다.
type hashKey struct {
	path string
	size int64
	mod  int64 // 수정시각, UnixNano
}

// FileHasher 는 파일의 sha256 을 구한다. 결과를 캐시하고 동시 호출에 안전하다.
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
// 오류로 올리지 않는다. 짧게 살다 죽은 프로세스의 이미지는 이미 지워져 있어 실패가 정상이다.
// nil 리시버도 받는다. 막으면 해시를 안 쓰는 센서가 호출부마다 nil 검사를 달아야 한다.
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
// 읽기에도 상한을 다시 건다. stat 과 open 사이에 파일이 커지면 상한이 무의미해진다.
// 넘치면 오류로 본다. 앞부분만의 해시를 돌려주면 그 값은 틀린 값이고 없는 것보다 나쁘다.
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
