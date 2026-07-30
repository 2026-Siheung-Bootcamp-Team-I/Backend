package transport

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/2026-Siheung-Bootcamp-Team-I/Backend/agent/internal/event"
)

type recorded struct {
	path    string
	nodeKey string
	body    map[string]any
}

// stub 은 docs/agent-protocol.md 의 서버 쪽을 흉내낸다.
type stub struct {
	server    *httptest.Server
	got       []recorded
	nodeKey   string
	commands  []Command
	eventFail int
}

func newStub(t *testing.T) *stub {
	t.Helper()
	s := &stub{nodeKey: "key-1"}
	mux := http.NewServeMux()

	mux.HandleFunc("/api/agent/enroll", func(w http.ResponseWriter, r *http.Request) {
		body := s.record(t, r)
		if body["enroll_secret"] != "secret" {
			http.Error(w, `{"error":"invalid_enroll_secret"}`, http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{"node_key": s.nodeKey})
	})

	mux.HandleFunc("/api/agent/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		if !s.authed(t, r, w) {
			return
		}
		writeJSON(w, map[string]any{
			"config": map[string]any{
				"sensors":                map[string]any{"process": true, "network": false},
				"watch_paths":            []string{"/Library/LaunchDaemons"},
				"flush_interval_seconds": 7,
			},
			"commands": s.commands,
		})
	})

	mux.HandleFunc("/api/agent/events", func(w http.ResponseWriter, r *http.Request) {
		if !s.authed(t, r, w) {
			return
		}
		if s.eventFail > 0 {
			s.eventFail--
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"accepted": 1})
	})

	mux.HandleFunc("/api/agent/command-result", func(w http.ResponseWriter, r *http.Request) {
		if !s.authed(t, r, w) {
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	s.server = httptest.NewServer(mux)
	t.Cleanup(s.server.Close)
	return s
}

func (s *stub) authed(t *testing.T, r *http.Request, w http.ResponseWriter) bool {
	t.Helper()
	s.record(t, r)
	if r.Header.Get("X-Node-Key") != s.nodeKey {
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	return true
}

func (s *stub) record(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	s.got = append(s.got, recorded{path: r.URL.Path, nodeKey: r.Header.Get("X-Node-Key"), body: body})
	return body
}

func (s *stub) calls(path string) []recorded {
	var out []recorded
	for _, r := range s.got {
		if r.path == path {
			out = append(out, r)
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

func newClient(s *stub) *Client {
	return NewClient(Config{
		BaseURL:      s.server.URL,
		EnrollSecret: "secret",
		HostID:       "mac-1",
		Platform:     "darwin",
		AgentVersion: "0.1.0",
		Timeout:      2 * time.Second,
	}, s.server.Client())
}

func enrolled(t *testing.T, s *stub) *Client {
	t.Helper()
	c := newClient(s)
	if err := c.Enroll(context.Background()); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	return c
}

func TestEnrollSendsContractFields(t *testing.T) {
	s := newStub(t)
	c := enrolled(t, s)

	body := s.calls("/api/agent/enroll")[0].body
	for key, want := range map[string]any{
		"enroll_secret":   "secret",
		"host_identifier": "mac-1",
		// 서버는 이 값에 windows 가 들어있는지로 갈랐다. GOOS 를 그대로 보낸다.
		"platform":      "darwin",
		"agent_version": "0.1.0",
	} {
		if body[key] != want {
			t.Errorf("enroll 본문 %q = %v, want %v", key, body[key], want)
		}
	}
	if c.NodeKey() != "key-1" {
		t.Errorf("NodeKey = %q, want key-1", c.NodeKey())
	}
}

func TestEnrollRejectsWrongSecret(t *testing.T) {
	s := newStub(t)
	c := NewClient(Config{BaseURL: s.server.URL, EnrollSecret: "wrong", HostID: "mac-1"}, s.server.Client())

	if err := c.Enroll(context.Background()); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}

func TestHeartbeatReturnsConfigAndCommands(t *testing.T) {
	s := newStub(t)
	s.commands = []Command{{ID: "c1", Type: CommandKillProcess, Target: "/tmp/evil.sh"}}
	c := enrolled(t, s)

	hb, err := c.Heartbeat(context.Background())
	if err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}

	if hb.Config.FlushIntervalSeconds != 7 {
		t.Errorf("flush = %d, want 7", hb.Config.FlushIntervalSeconds)
	}
	if len(hb.Config.WatchPaths) != 1 || hb.Config.WatchPaths[0] != "/Library/LaunchDaemons" {
		t.Errorf("watch_paths = %v", hb.Config.WatchPaths)
	}
	if len(hb.Commands) != 1 || hb.Commands[0].Target != "/tmp/evil.sh" {
		t.Fatalf("commands = %+v", hb.Commands)
	}
	// node_key 는 본문이 아니라 헤더로 간다.
	if s.calls("/api/agent/heartbeat")[0].nodeKey != "key-1" {
		t.Error("X-Node-Key 헤더가 안 실렸다")
	}
}

func TestServerConfigEnabled(t *testing.T) {
	cfg := ServerConfig{Sensors: map[string]bool{"process": true, "network": false}}

	if !cfg.Enabled("process") {
		t.Error("process 가 켜져 있어야 한다")
	}
	if cfg.Enabled("network") {
		t.Error("network 는 꺼져 있어야 한다")
	}
	// 서버가 언급하지 않은 센서는 켠 것으로 본다. 설정 누락으로 수집이 조용히 멈추면 안 된다.
	if !cfg.Enabled("file") {
		t.Error("언급 없는 센서는 켜져 있어야 한다")
	}
	if !(ServerConfig{}).Enabled("process") {
		t.Error("설정이 아예 없으면 전부 켜져 있어야 한다")
	}
}

func TestSendEventsPostsEnvelope(t *testing.T) {
	s := newStub(t)
	c := enrolled(t, s)

	f := event.Factory{Host: "mac-1"}
	e := f.Process(time.Unix(1, 0), event.ProcessInfo{Path: "/bin/sh", Cmdline: "sh", Parent: "bash"})
	err := c.SendEvents(context.Background(), []event.Event{e})
	if err != nil {
		t.Fatalf("SendEvents: %v", err)
	}

	body := s.calls("/api/agent/events")[0].body
	data, ok := body["events"].([]any)
	if !ok || len(data) != 1 {
		t.Fatalf("events = %#v", body["events"])
	}
}

func TestSendEventsSkipsEmptyBatch(t *testing.T) {
	s := newStub(t)
	c := enrolled(t, s)

	if err := c.SendEvents(context.Background(), nil); err != nil {
		t.Fatalf("SendEvents: %v", err)
	}
	if n := len(s.calls("/api/agent/events")); n != 0 {
		t.Errorf("빈 배치로 %d 회 호출, want 0", n)
	}
}

func TestSendEventsFailsOnServerError(t *testing.T) {
	// 5xx 를 조용히 삼키면 호출자가 배치를 되돌리지 못해 이벤트가 사라진다.
	s := newStub(t)
	c := enrolled(t, s)
	s.eventFail = 1

	if err := c.SendEvents(context.Background(), []event.Event{{Type: event.TypeProcess}}); err == nil {
		t.Fatal("5xx 인데 err 가 nil 이다")
	}
}

func TestReEnrollsOnUnauthorized(t *testing.T) {
	// 서버가 재시작해 키를 갈아치워도 사람이 손대지 않고 복구되어야 한다.
	s := newStub(t)
	c := enrolled(t, s)
	s.nodeKey = "key-2"

	if err := c.SendEvents(context.Background(), []event.Event{{Type: event.TypeProcess}}); err != nil {
		t.Fatalf("SendEvents: %v", err)
	}

	if c.NodeKey() != "key-2" {
		t.Errorf("NodeKey = %q, want key-2", c.NodeKey())
	}
	calls := s.calls("/api/agent/events")
	if len(calls) != 2 {
		t.Fatalf("events 호출 %d 회, want 2 (거부 1 + 재등록 후 1)", len(calls))
	}
	if calls[1].nodeKey != "key-2" {
		t.Errorf("재시도 node_key = %q, want key-2", calls[1].nodeKey)
	}
}

func TestReportCommandSendsResult(t *testing.T) {
	s := newStub(t)
	c := enrolled(t, s)

	err := c.ReportCommand(context.Background(), CommandResult{
		CommandID: "c1", Status: StatusKilled, Message: "pid 42 종료",
	})
	if err != nil {
		t.Fatalf("ReportCommand: %v", err)
	}

	body := s.calls("/api/agent/command-result")[0].body
	if body["command_id"] != "c1" || body["status"] != StatusKilled {
		t.Errorf("결과 본문 = %v", body)
	}
}
