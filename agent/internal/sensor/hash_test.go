package sensor

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// writeFile 은 내용을 담은 임시 파일을 만들고 경로를 준다.
func writeFile(t *testing.T, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("임시 파일을 만들지 못했다: %v", err)
	}
	return path
}

func wantSHA(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func TestFileHasherHashesContent(t *testing.T) {
	content := []byte("#!/bin/sh\necho hi\n")
	path := writeFile(t, "x.sh", content)

	h := NewFileHasher()
	got := h.Hash(path)

	if want := wantSHA(content); got != want {
		t.Errorf("Hash = %q, want %q", got, want)
	}
	// 소문자 16진수 64자여야 서버 쪽 해시 목록과 그대로 견줄 수 있다.
	if len(got) != 64 || strings.ToLower(got) != got {
		t.Errorf("해시 표기가 어긋난다: %q", got)
	}
	if s := h.Stats(); s.Hashed != 1 || s.Cached != 0 {
		t.Errorf("Stats = %+v, want Hashed 1", s)
	}
}

// 실행 파일은 거의 바뀌지 않는데 프로세스가 뜰 때마다 다시 읽으면 디스크를 통째로 먹는다.
func TestFileHasherCachesByPathSizeAndModTime(t *testing.T) {
	content := []byte("same content")
	path := writeFile(t, "bin", content)

	h := NewFileHasher()
	first := h.Hash(path)
	second := h.Hash(path)

	if first != second {
		t.Errorf("같은 파일인데 해시가 다르다: %q, %q", first, second)
	}
	s := h.Stats()
	if s.Hashed != 1 || s.Cached != 1 {
		t.Errorf("Stats = %+v, want Hashed 1 / Cached 1", s)
	}
}

// 캐시 키에 크기와 수정시각이 들어가야 내용이 바뀐 파일을 다시 읽는다.
// 경로만 키로 쓰면 같은 이름으로 덮어쓴 악성코드가 예전 해시를 달고 올라간다.
func TestFileHasherRehashesWhenFileChanges(t *testing.T) {
	path := writeFile(t, "bin", []byte("old"))

	h := NewFileHasher()
	first := h.Hash(path)

	changed := []byte("brand new content")
	if err := os.WriteFile(path, changed, 0o600); err != nil {
		t.Fatal(err)
	}

	if got := h.Hash(path); got != wantSHA(changed) {
		t.Errorf("바뀐 파일을 다시 읽지 않았다: %q, want %q", got, wantSHA(changed))
	}
	if first == wantSHA(changed) {
		t.Fatal("시험 자체가 잘못됐다. 두 내용의 해시가 같다")
	}
}

func TestFileHasherSkipsBigFiles(t *testing.T) {
	path := writeFile(t, "big", []byte("0123456789"))

	h := NewFileHasher()
	h.maxBytes = 4

	if got := h.Hash(path); got != "" {
		t.Errorf("Hash = %q, 상한을 넘으면 빈 값이어야 한다", got)
	}
	if s := h.Stats(); s.TooBig != 1 || s.Hashed != 0 {
		t.Errorf("Stats = %+v, want TooBig 1", s)
	}
}

func TestFileHasherReturnsEmptyOnUnreadable(t *testing.T) {
	dir := t.TempDir()

	cases := map[string]string{
		"없는 파일":   filepath.Join(dir, "gone"),
		"디렉터리":    dir,
		"빈 경로":    "",
		"권한 없는 것": "/dev/null/impossible",
	}

	h := NewFileHasher()
	for name, path := range cases {
		t.Run(name, func(t *testing.T) {
			if got := h.Hash(path); got != "" {
				t.Errorf("Hash(%q) = %q, want 빈 값", path, got)
			}
		})
	}

	// 빈 경로는 애초에 물어본 것이 아니므로 실패로 세지 않는다. 나머지 셋은 세어야
	// "해시가 전부 비어 있다" 는 상태의 원인을 로그에서 알 수 있다.
	if s := h.Stats(); s.Failed != 3 {
		t.Errorf("Stats = %+v, want Failed 3", s)
	}
}

// 오래 도는 에이전트에서 맵이 무한정 커지면 안 된다.
func TestFileHasherCapsCacheSize(t *testing.T) {
	dir := t.TempDir()
	h := NewFileHasher()
	h.maxEntries = 2

	for i := 0; i < 5; i++ {
		path := filepath.Join(dir, string(rune('a'+i)))
		if err := os.WriteFile(path, []byte{byte(i)}, 0o600); err != nil {
			t.Fatal(err)
		}
		if h.Hash(path) == "" {
			t.Fatalf("%s 를 해시하지 못했다", path)
		}
	}

	if got := h.size(); got > 2 {
		t.Errorf("캐시 항목 수 = %d, 상한 2 를 넘었다", got)
	}
}

// 해시 캐시는 센서 여러 개가 같이 쓰는 공유 상태다. -race 로 돌린다.
func TestFileHasherIsSafeForConcurrentUse(t *testing.T) {
	content := []byte("shared")
	path := writeFile(t, "shared", content)

	h := NewFileHasher()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := h.Hash(path); got != wantSHA(content) {
				t.Errorf("Hash = %q, want %q", got, wantSHA(content))
			}
		}()
	}
	wg.Wait()
}
