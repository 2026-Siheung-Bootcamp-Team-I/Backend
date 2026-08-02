package sensor

import (
	"sync"
	"time"
)

// PID 를 프로세스 이름/경로로 푸는 조회를 짧게 캐시한다.
// 매핑(etw_map.go)과 흐름 기억(flowowners.go)이 같이 쓰므로 어느 한쪽에 두지 않는다.

// ProcessNamer 는 PID 로 그 프로세스의 이름 또는 이미지 경로를 찾는다. 못 찾으면 빈 문자열이다.
type ProcessNamer interface {
	Name(pid int) string
}

const (
	// pidCacheTTL 은 캐시한 경로를 믿는 시간이다.
	// 길게 늘리면 Windows 가 재사용한 PID 의 새 프로세스에 죽은 프로세스 이름이 붙는다.
	pidCacheTTL = 2 * time.Second
	// pidCacheMax 는 항목 수 상한이다. 넘으면 통째로 비운다.
	// 상한을 풀면 오래 도는 에이전트에서 맵이 무한정 커진다.
	pidCacheMax = 1024
)

// pidCache 는 PID 를 이미지 경로로 푼 결과를 짧게 들고 있는다.
// 실제 조회는 Windows API 라 lookup 으로 주입받는다.
type pidCache struct {
	mu      sync.Mutex
	entries map[int]pidEntry
	lookup  func(pid int) string
	// now 가 비면 time.Now 를 쓴다. 만료를 테스트에서 흔들어 보려고 둔다.
	now func() time.Time
}

type pidEntry struct {
	path string
	at   time.Time
}

// Name 은 PID 의 이미지 경로를 준다. ProcessNamer 를 만족한다.
// 실패(빈 문자열)도 캐시한다. 안 하면 죽은 프로세스의 연결이 남은 동안 이벤트마다 조회를 다시 한다.
func (c *pidCache) Name(pid int) string {
	now := c.clock()

	c.mu.Lock()
	if e, ok := c.entries[pid]; ok && now.Sub(e.at) < pidCacheTTL {
		c.mu.Unlock()
		return e.path
	}
	c.mu.Unlock()

	// 조회는 락 밖에서 한다. 조회가 막히면 다른 이벤트 처리까지 같이 멈춘다.
	path := c.lookup(pid)

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil || len(c.entries) >= pidCacheMax {
		c.entries = make(map[int]pidEntry, pidCacheMax)
	}
	c.entries[pid] = pidEntry{path: path, at: now}
	return path
}

func (c *pidCache) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}
